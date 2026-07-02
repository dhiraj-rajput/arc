//! Machine capacity detection.
//!
//! Detects the host machine's capabilities at startup and exposes adaptive
//! configuration for parallelism, chunk sizes, and cipher selection.
//!
//! This is the single source of truth for all capacity-dependent decisions in arc.

use std::sync::OnceLock;
use tracing::{debug, info};

/// Global machine capacity — detected once at startup.
static MACHINE_CAPACITY: OnceLock<MachineCapacity> = OnceLock::new();

/// Hardware capabilities and limits of the current machine.
///
/// Used throughout arc-core to make adaptive decisions about parallelism,
/// chunk sizes, memory budgets, and cryptographic algorithm selection.
#[derive(Debug, Clone)]
pub struct MachineCapacity {
    /// Total logical CPUs (including hyperthreads).
    pub logical_cpus: usize,
    /// Physical CPU cores (not hyperthreads).
    pub physical_cpus: usize,
    /// Total RAM in MiB.
    pub total_memory_mib: u64,
    /// Available RAM in MiB at detection time.
    pub available_memory_mib: u64,
    /// Whether the CPU has hardware AES-NI instructions (x86_64 only).
    /// When true, AES-256-GCM is faster than ChaCha20-Poly1305.
    pub has_aes_ni: bool,
    /// Whether the CPU has AVX2 instructions.
    /// BLAKE3 uses AVX2 automatically via its crate — this is for logging only.
    pub has_avx2: bool,
    /// Whether the CPU has AVX-512 instructions.
    pub has_avx512: bool,
    /// OS / architecture string (for diagnostics).
    pub platform: String,
}

impl MachineCapacity {
    /// Detect the current machine's capacity.
    ///
    /// This performs CPU feature detection and queries the OS for memory info.
    /// Safe to call from multiple threads — the detection runs only once.
    pub fn detect() -> &'static MachineCapacity {
        MACHINE_CAPACITY.get_or_init(|| {
            let cap = Self::detect_inner();
            info!(
                logical_cpus = cap.logical_cpus,
                physical_cpus = cap.physical_cpus,
                available_memory_mib = cap.available_memory_mib,
                has_aes_ni = cap.has_aes_ni,
                has_avx2 = cap.has_avx2,
                has_avx512 = cap.has_avx512,
                platform = %cap.platform,
                "machine capacity detected"
            );
            cap
        })
    }

    fn detect_inner() -> MachineCapacity {
        let logical_cpus = num_cpus::get();
        let physical_cpus = num_cpus::get_physical();

        // Memory via sysinfo
        let (total_memory_mib, available_memory_mib) = {
            use sysinfo::System;
            let sys = System::new_all();
            (
                sys.total_memory() / (1024 * 1024),
                sys.available_memory() / (1024 * 1024),
            )
        };

        // CPU feature detection (x86_64 only; other arches default to false)
        #[cfg(target_arch = "x86_64")]
        let (has_aes_ni, has_avx2, has_avx512) = {
            let aes = std::arch::is_x86_feature_detected!("aes");
            let avx2 = std::arch::is_x86_feature_detected!("avx2");
            let avx512 = std::arch::is_x86_feature_detected!("avx512f");
            (aes, avx2, avx512)
        };
        #[cfg(not(target_arch = "x86_64"))]
        let (has_aes_ni, has_avx2, has_avx512) = (false, false, false);

        let platform = format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH);

        debug!(
            physical_cpus,
            logical_cpus,
            total_memory_mib,
            available_memory_mib,
            has_aes_ni,
            has_avx2,
            has_avx512,
            platform = %platform,
            "raw machine capacity"
        );

        MachineCapacity {
            logical_cpus,
            physical_cpus,
            total_memory_mib,
            available_memory_mib,
            has_aes_ni,
            has_avx2,
            has_avx512,
            platform,
        }
    }

    // ─── Derived Configuration ──────────────────────────────────────────────

    /// Number of parallel chunk streams to use during a file transfer.
    ///
    /// Scales with physical CPU cores, capped at 64.
    /// On battery-saver mode (caller sets `battery_saver = true`), reduced to 2.
    pub fn optimal_parallel_chunks(&self, battery_saver: bool) -> usize {
        if battery_saver {
            return 2;
        }
        // Use physical cores (not logical) to avoid HT contention on pure compute
        let base = self.physical_cpus;
        base.clamp(1, 64)
    }

    /// Optimal chunk size in bytes for a file of the given size.
    ///
    /// Implements the table from §6.3 of the master plan:
    /// < 64 KB         → whole file
    /// 64 KB – 1 MB    → 256 KB
    /// 1 MB – 100 MB   → 1 MB
    /// 100 MB – 1 GB   → 4 MB
    /// 1 GB – 4 GB     → 32 MB
    /// > 4 GB          → 64 MB
    pub fn optimal_chunk_size(&self, file_size: u64) -> u32 {
        const KB: u64 = 1024;
        const MB: u64 = 1024 * 1024;

        match file_size {
            0..=65_535 => file_size as u32, // whole file, no chunking
            65_536..=1_048_575 => (256 * KB) as u32,
            1_048_576..=104_857_599 => MB as u32,
            104_857_600..=1_073_741_823 => (4 * MB) as u32,
            1_073_741_824..=4_294_967_295 => (32 * MB) as u32,
            _ => (64 * MB) as u32,
        }
    }

    /// Total memory budget for in-flight chunk buffers, in bytes.
    ///
    /// We use at most 5% of available RAM for transfer buffers,
    /// capped between 32 MB and 512 MB to prevent OOM on small machines.
    pub fn memory_budget_bytes(&self) -> u64 {
        let five_pct = self.available_memory_mib * 1024 * 1024 / 20;
        five_pct.clamp(32 * 1024 * 1024, 512 * 1024 * 1024)
    }

    /// Number of buffers per pipeline stage (read → compress → encrypt → hash → queue).
    ///
    /// Higher values → more RAM used but smoother pipeline throughput.
    /// On machines with ≥ 8 GB available, use 8 buffers per stage.
    pub fn pipeline_buffer_count(&self) -> usize {
        match self.available_memory_mib {
            0..=1999 => 2,
            2000..=7999 => 4,
            _ => 8,
        }
    }

    /// Whether to prefer AES-256-GCM over ChaCha20-Poly1305.
    ///
    /// On x86_64 with AES-NI, AES-GCM is ~15 GB/s vs ~4 GB/s for ChaCha20.
    /// On ARM or x86 without AES-NI, ChaCha20 wins.
    pub fn prefer_aes_gcm(&self) -> bool {
        self.has_aes_ni
    }

    /// Number of read-ahead chunks (how many chunks to read from disk before
    /// the current network send position).
    pub fn read_ahead_chunks(&self) -> usize {
        // Scale with physical CPUs so disk I/O saturates the CPU pipeline
        (self.physical_cpus * 2).clamp(2, 32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_machine_capacity_detect() {
        let cap = MachineCapacity::detect();
        // Basic sanity: must have at least 1 CPU and 128 MiB RAM
        assert!(cap.logical_cpus >= 1, "must have at least 1 logical CPU");
        assert!(cap.physical_cpus >= 1, "must have at least 1 physical CPU");
        assert!(
            cap.total_memory_mib >= 128,
            "must have at least 128 MiB RAM"
        );
        assert!(
            !cap.platform.is_empty(),
            "platform string must not be empty"
        );
    }

    #[test]
    fn test_optimal_chunk_size() {
        let cap = MachineCapacity::detect();

        // Whole file for tiny files
        assert_eq!(cap.optimal_chunk_size(1_000), 1_000);

        // 256 KB for small files
        assert_eq!(cap.optimal_chunk_size(500_000), 256 * 1024);

        // 1 MB for medium files
        assert_eq!(cap.optimal_chunk_size(10 * 1024 * 1024), 1024 * 1024);

        // 4 MB for large files
        assert_eq!(cap.optimal_chunk_size(200 * 1024 * 1024), 4 * 1024 * 1024);

        // 32 MB for very large files to reduce per-chunk RTT overhead
        assert_eq!(
            cap.optimal_chunk_size(2 * 1024 * 1024 * 1024),
            32 * 1024 * 1024
        );
    }

    #[test]
    fn test_memory_budget_reasonable() {
        let cap = MachineCapacity::detect();
        let budget = cap.memory_budget_bytes();
        // Must be between 32 MB and 512 MB
        assert!(budget >= 32 * 1024 * 1024, "budget below minimum");
        assert!(budget <= 512 * 1024 * 1024, "budget above maximum");
    }

    #[test]
    fn test_parallel_chunks_battery_saver() {
        let cap = MachineCapacity::detect();
        assert_eq!(
            cap.optimal_parallel_chunks(true),
            2,
            "battery saver must use 2 chunks"
        );
        assert!(
            cap.optimal_parallel_chunks(false) >= 1,
            "normal mode must use at least 1 chunk stream"
        );
    }

    #[test]
    fn test_detect_idempotent() {
        // Calling detect() twice returns the same reference
        let a = MachineCapacity::detect();
        let b = MachineCapacity::detect();
        assert_eq!(a.logical_cpus, b.logical_cpus);
    }
}
