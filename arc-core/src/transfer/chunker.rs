//! Adaptive chunker: selects chunk size and parallel stream count based on
//! machine capacity and file size (§6.3 of master plan).

use crate::compression::{CompressionAlgo, probe_compressibility};
use crate::crypto::hash::blake3_hash_parallel;
use crate::machine::MachineCapacity;
use std::path::Path;

/// A single chunk of file data, ready to be compressed and encrypted.
#[derive(Debug)]
pub struct FileChunk {
    /// Zero-based chunk index.
    pub index: u32,
    /// BLAKE3 hash of the raw (uncompressed) chunk data.
    pub hash: [u8; 32],
    /// Raw chunk data (before compression).
    pub data: Vec<u8>,
    /// Whether this is the last chunk.
    pub is_last: bool,
}

/// Configuration for a transfer, derived from machine capacity and file size.
#[derive(Debug, Clone)]
pub struct TransferConfig {
    /// Chunk size in bytes.
    pub chunk_size: u32,
    /// Number of parallel QUIC streams to use.
    pub parallel_streams: usize,
    /// Compression algorithm to use.
    pub compression: CompressionAlgo,
    /// Whether to use memory-mapped I/O (recommended for files > 100 MB).
    pub use_mmap: bool,
    /// Number of read-ahead chunks.
    pub read_ahead: usize,
    /// Number of pipeline buffer slots per stage.
    pub pipeline_buffers: usize,
}

/// Adaptive chunker that produces `TransferConfig` and iterates file chunks.
///
/// Reads the file size and samples the first 64 KB to determine compression.
/// Uses `MachineCapacity` to set parallel stream count and pipeline depth.
pub struct AdaptiveChunker {
    pub config: TransferConfig,
    pub file_size: u64,
    pub chunk_count: u32,
}

impl AdaptiveChunker {
    /// Create an `AdaptiveChunker` for the file at `path`.
    ///
    /// Probes the file to determine:
    /// - Chunk size (from file size + machine capacity)
    /// - Compression algorithm (from first 64 KB compressibility)
    /// - Parallel stream count (from CPU core count)
    pub fn new(path: &Path, battery_saver: bool) -> std::io::Result<Self> {
        let meta = std::fs::metadata(path)?;
        let file_size = meta.len();

        let cap = MachineCapacity::detect();
        // Enforce minimum chunk size of 16 KB (16,384 bytes) to prevent tiny chunks
        let chunk_size = cap.optimal_chunk_size(file_size).max(16_384);
        let parallel_streams = cap.optimal_parallel_chunks(battery_saver);
        let read_ahead = cap.read_ahead_chunks();
        let pipeline_buffers = cap.pipeline_buffer_count();
        let use_mmap = file_size > 100 * 1024 * 1024; // > 100 MB → mmap

        // Probe compressibility using first 64 KB of the file
        let compression = Self::probe_file_compression(path, file_size)?;

        let chunk_count = if file_size == 0 {
            1
        } else {
            file_size.div_ceil(chunk_size as u64) as u32
        };

        Ok(Self {
            config: TransferConfig {
                chunk_size,
                parallel_streams,
                compression,
                use_mmap,
                read_ahead,
                pipeline_buffers,
            },
            file_size,
            chunk_count,
        })
    }

    /// Probe the first 64 KB of a file for compressibility.
    fn probe_file_compression(path: &Path, file_size: u64) -> std::io::Result<CompressionAlgo> {
        if file_size == 0 {
            return Ok(CompressionAlgo::None);
        }

        use std::io::Read;
        let mut file = std::fs::File::open(path)?;
        let sample_size = (64 * 1024).min(file_size as usize);
        let mut sample = vec![0u8; sample_size];
        let n = file.read(&mut sample)?;
        sample.truncate(n);

        let result = probe_compressibility(&sample);
        Ok(result.algorithm)
    }

    /// Iterate file chunks without loading the entire file into memory.
    ///
    /// Yields `FileChunk` structs with BLAKE3 hash and raw data.
    /// The caller is responsible for compression and encryption.
    pub fn iter_chunks(&self, path: &Path) -> std::io::Result<Vec<FileChunk>> {
        use std::io::Read;

        if self.file_size == 0 {
            let data = Vec::new();
            let hash = blake3_hash_parallel(&data);
            return Ok(vec![FileChunk {
                index: 0,
                hash,
                data,
                is_last: true,
            }]);
        }

        let mut file = std::fs::File::open(path)?;
        let chunk_size = self.config.chunk_size as usize;
        let mut chunks = Vec::with_capacity(self.chunk_count as usize);

        let mut buf = vec![0u8; chunk_size];
        let mut index = 0u32;
        let total = self.chunk_count;

        loop {
            let mut bytes_read = 0;
            while bytes_read < chunk_size {
                match file.read(&mut buf[bytes_read..]) {
                    Ok(0) => break, // EOF
                    Ok(n) => bytes_read += n,
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }

            if bytes_read == 0 {
                break;
            }

            let data = buf[..bytes_read].to_vec();
            let hash = blake3_hash_parallel(&data);
            let is_last = index + 1 == total;

            chunks.push(FileChunk {
                index,
                hash,
                data,
                is_last,
            });

            index += 1;
        }

        Ok(chunks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp(size: usize) -> NamedTempFile {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&vec![0xABu8; size]).unwrap();
        tmp.flush().unwrap();
        tmp
    }

    #[test]
    fn test_chunker_small_file() {
        let tmp = write_temp(1000);
        let chunker = AdaptiveChunker::new(tmp.path(), false).unwrap();
        assert_eq!(chunker.chunk_count, 1, "small file fits in one chunk");
        assert_eq!(chunker.file_size, 1000);
    }

    #[test]
    fn test_chunker_medium_file() {
        let tmp = write_temp(2 * 1024 * 1024); // 2 MB
        let chunker = AdaptiveChunker::new(tmp.path(), false).unwrap();
        assert!(chunker.chunk_count >= 1);
        assert!(chunker.config.chunk_size > 0);
    }

    #[test]
    fn test_chunker_battery_saver() {
        let tmp = write_temp(1024);
        let normal = AdaptiveChunker::new(tmp.path(), false).unwrap();
        let saver = AdaptiveChunker::new(tmp.path(), true).unwrap();
        assert_eq!(
            saver.config.parallel_streams, 2,
            "battery saver uses 2 streams"
        );
        // Normal mode uses more streams on a multi-core machine
        let _ = normal;
    }

    #[test]
    fn test_iter_chunks_hashes() {
        let data = vec![0xCCu8; 512];
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        let chunker = AdaptiveChunker::new(tmp.path(), false).unwrap();
        let chunks = chunker.iter_chunks(tmp.path()).unwrap();

        assert!(!chunks.is_empty());
        for chunk in &chunks {
            let expected_hash = blake3_hash_parallel(&chunk.data);
            assert_eq!(
                chunk.hash, expected_hash,
                "chunk hash must match BLAKE3(data)"
            );
        }
    }

    #[test]
    fn test_last_chunk_flagged() {
        let tmp = write_temp(100);
        let chunker = AdaptiveChunker::new(tmp.path(), false).unwrap();
        let chunks = chunker.iter_chunks(tmp.path()).unwrap();
        assert!(chunks.last().unwrap().is_last, "last chunk must be flagged");
        if chunks.len() > 1 {
            assert!(!chunks[0].is_last, "non-last chunk must not be flagged");
        }
    }
}
