//! Disk-persisted transfer resume state (§17 transition table).
//!
//! When a transfer is interrupted (network drop, crash), arc can resume it
//! by re-requesting only the missing chunks. The receiver tracks which chunks
//! it has received as a bitmap stored in SQLite.
//!
//! This is the "resume bitmap" sent in `TransferAccept.resume_bitmap`.

use std::collections::HashSet;

#[derive(serde::Serialize, serde::Deserialize)]
struct DiskResumeState {
    total_chunks: u32,
    file_hash: String,
    bitmap_hex: String,
}

/// Resume state for a transfer: tracks received chunk indices.
///
/// Serialized as a compact byte bitmap: bit `i` of byte `i/8` is set if chunk `i` was received.
#[derive(Debug, Clone)]
pub struct ResumeState {
    /// Total number of chunks in this transfer.
    pub total_chunks: u32,
    /// Expected file hash of the transfer.
    pub file_hash: [u8; 32],
    /// Set of chunk indices that have been successfully received and verified.
    received: HashSet<u32>,
}

impl ResumeState {
    /// Create a new empty resume state.
    pub fn new(total_chunks: u32, file_hash: [u8; 32]) -> Self {
        Self {
            total_chunks,
            file_hash,
            received: HashSet::new(),
        }
    }

    /// Mark a chunk as successfully received.
    pub fn mark_received(&mut self, index: u32) {
        self.received.insert(index);
    }

    /// Returns true if all chunks have been received.
    pub fn is_complete(&self) -> bool {
        self.received.len() as u32 == self.total_chunks
    }

    /// Returns the set of missing chunk indices.
    pub fn missing_chunks(&self) -> Vec<u32> {
        (0..self.total_chunks)
            .filter(|i| !self.received.contains(i))
            .collect()
    }

    /// Serialize to a compact bitmap (one bit per chunk).
    ///
    /// Bit `i % 8` of byte `i / 8` is set if chunk `i` is received.
    pub fn to_bitmap(&self) -> Vec<u8> {
        let byte_len = (self.total_chunks as usize).div_ceil(8);
        let mut bitmap = vec![0u8; byte_len];
        for &idx in &self.received {
            if idx < self.total_chunks {
                bitmap[idx as usize / 8] |= 1 << (idx % 8);
            }
        }
        bitmap
    }

    /// Deserialize from a bitmap (inverse of `to_bitmap`).
    pub fn from_bitmap(bitmap: &[u8], total_chunks: u32) -> Self {
        let mut received = HashSet::new();
        for idx in 0..total_chunks {
            let byte = idx as usize / 8;
            let bit = idx % 8;
            if byte < bitmap.len() && (bitmap[byte] >> bit) & 1 == 1 {
                received.insert(idx);
            }
        }
        Self { total_chunks, file_hash: [0u8; 32], received }
    }

    /// Number of chunks received so far.
    pub fn received_count(&self) -> u32 {
        self.received.len() as u32
    }

    /// Progress as a fraction in [0.0, 1.0].
    pub fn progress(&self) -> f64 {
        if self.total_chunks == 0 {
            1.0
        } else {
            self.received.len() as f64 / self.total_chunks as f64
        }
    }

    /// Save the resume state to a config sub-directory.
    pub fn save_to_disk(&self, transfer_id: &[u8; 16]) -> Result<(), anyhow::Error> {
        let path = get_resume_path(transfer_id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let state = DiskResumeState {
            total_chunks: self.total_chunks,
            file_hash: hex::encode(self.file_hash),
            bitmap_hex: hex::encode(self.to_bitmap()),
        };
        let content = serde_json::to_string_pretty(&state)?;
        std::fs::write(&path, content)?;
        Ok(())
    }

    /// Load the resume state from disk if it exists.
    pub fn load_from_disk(transfer_id: &[u8; 16], expected_file_hash: [u8; 32], total_chunks: u32) -> Result<Self, anyhow::Error> {
        let path = get_resume_path(transfer_id);
        let content = std::fs::read_to_string(&path)?;
        let disk_state: DiskResumeState = serde_json::from_str(&content)?;
        
        let file_hash_bytes = hex::decode(&disk_state.file_hash)?;
        if file_hash_bytes != expected_file_hash {
            return Err(anyhow::anyhow!("file hash mismatch for resumed transfer"));
        }
        if disk_state.total_chunks != total_chunks {
            return Err(anyhow::anyhow!("total chunks mismatch for resumed transfer"));
        }

        let bitmap = hex::decode(&disk_state.bitmap_hex)?;
        let mut state = Self::from_bitmap(&bitmap, total_chunks);
        state.file_hash = expected_file_hash;
        Ok(state)
    }

    /// Delete the resume state from disk (call upon successful transfer).
    pub fn delete_from_disk(transfer_id: &[u8; 16]) -> Result<(), anyhow::Error> {
        let path = get_resume_path(transfer_id);
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}

fn get_resume_path(transfer_id: &[u8; 16]) -> std::path::PathBuf {
    let mut p = crate::storage::get_config_path();
    p.pop(); // remove config.json
    p.push("resume");
    p.push(format!("{}.json", hex::encode(transfer_id)));
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resume_state_empty() {
        let state = ResumeState::new(10, [0u8; 32]);
        assert!(!state.is_complete());
        assert_eq!(state.received_count(), 0);
        assert_eq!(state.missing_chunks().len(), 10);
    }

    #[test]
    fn test_resume_state_complete() {
        let mut state = ResumeState::new(5, [0u8; 32]);
        for i in 0..5 {
            state.mark_received(i);
        }
        assert!(state.is_complete());
        assert_eq!(state.missing_chunks().len(), 0);
        assert_eq!(state.progress(), 1.0);
    }

    #[test]
    fn test_resume_state_partial() {
        let mut state = ResumeState::new(4, [0u8; 32]);
        state.mark_received(0);
        state.mark_received(2);

        assert!(!state.is_complete());
        let missing = state.missing_chunks();
        assert!(missing.contains(&1));
        assert!(missing.contains(&3));
        assert!(!missing.contains(&0));
        assert!(!missing.contains(&2));
    }

    #[test]
    fn test_bitmap_roundtrip() {
        let mut state = ResumeState::new(16, [0u8; 32]);
        state.mark_received(0);
        state.mark_received(3);
        state.mark_received(7);
        state.mark_received(15);

        let bitmap = state.to_bitmap();
        let restored = ResumeState::from_bitmap(&bitmap, 16);

        assert_eq!(restored.received_count(), state.received_count());
        assert_eq!(restored.missing_chunks(), state.missing_chunks());
    }

    #[test]
    fn test_bitmap_zero_chunks() {
        let state = ResumeState::new(0, [0u8; 32]);
        assert!(state.is_complete());
        let bitmap = state.to_bitmap();
        assert!(bitmap.is_empty());
    }

    #[test]
    fn test_progress() {
        let mut state = ResumeState::new(4, [0u8; 32]);
        assert_eq!(state.progress(), 0.0);
        state.mark_received(0);
        assert!((state.progress() - 0.25).abs() < f64::EPSILON);
        state.mark_received(1);
        state.mark_received(2);
        state.mark_received(3);
        assert_eq!(state.progress(), 1.0);
    }
}
