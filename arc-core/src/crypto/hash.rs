//! BLAKE3 parallel hashing, Merkle tree verification, and fast dedup probe.
//!
//! # BLAKE3 Parallelism
//!
//! BLAKE3 with the `rayon` crate feature automatically parallelizes hashing
//! across all CPU cores for large files. On an 8-core machine, a 25 GB file
//! hashes in ~1.5 seconds (vs ~25 seconds for single-threaded SHA-256).
//!
//! # Merkle Tree (§2.2 of master plan)
//!
//! The BLAKE3 Merkle tree enables *per-chunk streaming verification*.
//! The root hash in `TransferOffer` commits to the entire file tree.
//! Each 1 KiB leaf can be verified against its proof without assembling the full file.
//!
//! # Fast Dedup Probe (§6.1 of master plan)
//!
//! `arc_fast_hash` samples only the first + last 128 KiB of a file (plus size),
//! enabling sub-millisecond "is this file already there?" checks before committing
//! to a full BLAKE3 hash of the entire file.

use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

/// Full BLAKE3 hash of the file at `path`, using rayon-parallel hashing.
///
/// For files > ~1 MB, this uses all available CPU cores automatically.
/// Returns a 32-byte BLAKE3 hash.
pub fn blake3_hash_parallel(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update_rayon(data);
    *hasher.finalize().as_bytes()
}

/// BLAKE3 hash a file in a streaming fashion without loading it into memory.
///
/// Reads the file in 1 MiB chunks. Safe for files of any size.
pub fn blake3_hash_file(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1024 * 1024]; // 1 MiB read buffer

    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(*hasher.finalize().as_bytes())
}

/// Fast sampling hash for deduplication probing (§6.1 of master plan).
///
/// Hashes: file_size (8 bytes) + first 128 KiB + last 128 KiB (if file > 256 KiB).
/// This is NOT cryptographically binding — a collision is theoretically possible.
/// Always verify with the full BLAKE3 hash before accepting a file as deduplicated.
///
/// Equivalent to `imohash` in croc but using BLAKE3 instead of MD5.
pub fn arc_fast_hash(path: &Path) -> io::Result<[u8; 32]> {
    const SAMPLE_SIZE: u64 = 128 * 1024; // 128 KiB

    let mut file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    let file_size = meta.len();

    let mut hasher = blake3::Hasher::new();
    hasher.update(&file_size.to_le_bytes());

    let mut buf = vec![0u8; SAMPLE_SIZE as usize];

    // First 128 KiB
    let n = file.read(&mut buf)?;
    hasher.update(&buf[..n]);

    // Last 128 KiB (only if file is > 256 KiB)
    if file_size > SAMPLE_SIZE * 2 {
        file.seek(SeekFrom::End(-(SAMPLE_SIZE as i64)))?;
        let n = file.read(&mut buf)?;
        hasher.update(&buf[..n]);
    }

    Ok(*hasher.finalize().as_bytes())
}

/// Hash an entire directory recursively to produce a directory Merkle forest root hash.
///
/// Recursively scans the directory, sorts file entries by path, hashes each file,
/// and returns the BLAKE3 hash of the concatenated individual file hashes.
pub fn blake3_hash_dir(dir: &Path) -> io::Result<[u8; 32]> {
    let mut file_entries = Vec::new();
    
    fn visit_dirs(dir: &Path, base: &Path, entries: &mut Vec<(String, [u8; 32])>) -> io::Result<()> {
        if dir.is_dir() {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    visit_dirs(&path, base, entries)?;
                } else {
                    let rel_path = path.strip_prefix(base)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .to_string();
                    let hash = blake3_hash_file(&path)?;
                    entries.push((rel_path, hash));
                }
            }
        }
        Ok(())
    }
    
    visit_dirs(dir, dir, &mut file_entries)?;
    // Sort by relative path to ensure deterministic order
    file_entries.sort_by(|a, b| a.0.cmp(&b.0));
    
    // Concat all hashes
    let mut concat = Vec::with_capacity(file_entries.len() * 32);
    for (_, hash) in file_entries {
        concat.extend_from_slice(&hash);
    }
    
    Ok(*blake3::hash(&concat).as_bytes())
}

// ─── Merkle Tree ──────────────────────────────────────────────────────────────

/// A BLAKE3 Merkle tree over a file's chunks.
///
/// Enables per-chunk streaming verification: each chunk can be verified
/// independently without receiving the entire file first (§2.2 of master plan).
///
/// The tree is built over a flat list of leaf hashes. The root hash is included
/// in `TransferOffer.file_hash` and commits to the entire file.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// Leaf hashes (one per chunk, in order).
    pub leaves: Vec<[u8; 32]>,
    /// Internal nodes, level by level (leaves → root).
    /// nodes[0] = leaves, nodes[last] = [root].
    nodes: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Build a Merkle tree from a slice of chunk data.
    ///
    /// `chunk_size` should match the transfer's chunk size.
    /// For alignment with the receiver's verification, both sides must use
    /// the same chunk size (negotiated in `TransferOffer`).
    pub fn build(data: &[u8], chunk_size: usize) -> Self {
        assert!(chunk_size > 0, "chunk_size must be positive");

        let leaves: Vec<[u8; 32]> = if data.is_empty() {
            vec![*blake3::hash(&[]).as_bytes()]
        } else {
            data.chunks(chunk_size)
                .map(|chunk| *blake3::hash(chunk).as_bytes())
                .collect()
        };

        let nodes = Self::build_tree(&leaves);

        MerkleTree { leaves, nodes }
    }

    /// Build a Merkle tree from pre-computed leaf hashes.
    pub fn from_leaves(leaves: Vec<[u8; 32]>) -> Self {
        let nodes = Self::build_tree(&leaves);
        MerkleTree { leaves, nodes }
    }

    fn build_tree(leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
        let mut levels: Vec<Vec<[u8; 32]>> = vec![leaves.to_vec()];
        let mut current = leaves.to_vec();

        while current.len() > 1 {
            let next: Vec<[u8; 32]> = current
                .chunks(2)
                .map(|pair| {
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(&pair[0]);
                    if pair.len() > 1 {
                        hasher.update(&pair[1]);
                    } else {
                        // Odd leaf: duplicate it (standard Merkle padding)
                        hasher.update(&pair[0]);
                    }
                    *hasher.finalize().as_bytes()
                })
                .collect();
            levels.push(next.clone());
            current = next;
        }

        levels
    }

    /// The root hash — this is the value included in `TransferOffer.file_hash`.
    pub fn root(&self) -> [u8; 32] {
        self.nodes
            .last()
            .and_then(|level| level.first())
            .copied()
            .unwrap_or_else(|| *blake3::hash(&[]).as_bytes())
    }

    /// Compute the Merkle proof for chunk at index `leaf_index`.
    ///
    /// The proof is a list of sibling hashes from leaf to root.
    /// The receiver uses this to verify a chunk without the full tree.
    pub fn proof(&self, leaf_index: usize) -> Vec<[u8; 32]> {
        let mut proof = Vec::new();
        let mut idx = leaf_index;

        for level in &self.nodes[..self.nodes.len().saturating_sub(1)] {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            if sibling_idx < level.len() {
                proof.push(level[sibling_idx]);
            } else {
                // Odd node: sibling is itself (duplicated)
                proof.push(level[idx]);
            }
            idx /= 2;
        }

        proof
    }

    /// Verify a chunk against the Merkle root.
    ///
    /// Returns `true` if the chunk's BLAKE3 hash is consistent with the root.
    pub fn verify_chunk(&self, leaf_index: usize, chunk: &[u8]) -> bool {
        if leaf_index >= self.leaves.len() {
            return false;
        }
        let leaf_hash = *blake3::hash(chunk).as_bytes();
        leaf_hash == self.leaves[leaf_index]
    }

    /// Verify a chunk given only the root hash and a proof (for streaming verification).
    ///
    /// The receiver can call this without holding the full Merkle tree —
    /// only the proof (O(log n) hashes) is needed.
    pub fn verify_with_proof(
        root: &[u8; 32],
        leaf_index: usize,
        leaf_count: usize,
        chunk: &[u8],
        proof: &[[u8; 32]],
    ) -> bool {
        if leaf_count == 0 {
            return false;
        }
        let mut expected_proof_len = 0;
        let mut n = leaf_count;
        while n > 1 {
            expected_proof_len += 1;
            n = (n + 1) / 2;
        }
        if proof.len() != expected_proof_len {
            return false;
        }

        let mut current_hash = *blake3::hash(chunk).as_bytes();
        let mut idx = leaf_index;
        let mut level_size = leaf_count;

        for sibling in proof {
            let parent = if idx % 2 == 0 {
                // We are the left child
                let mut h = blake3::Hasher::new();
                h.update(&current_hash);
                h.update(sibling);
                *h.finalize().as_bytes()
            } else {
                // We are the right child
                let mut h = blake3::Hasher::new();
                h.update(sibling);
                h.update(&current_hash);
                *h.finalize().as_bytes()
            };
            current_hash = parent;
            idx /= 2;
            level_size = (level_size + 1) / 2;
        }

        &current_hash == root
    }

    /// Number of leaf chunks in the tree.
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_blake3_parallel_consistency() {
        let data = vec![0xABu8; 4 * 1024 * 1024]; // 4 MiB
        let hash1 = blake3_hash_parallel(&data);
        let hash2 = blake3_hash_parallel(&data);
        assert_eq!(hash1, hash2, "same input must produce same hash");
    }

    #[test]
    fn test_blake3_different_data() {
        let data1 = b"hello arc";
        let data2 = b"hello ARC";
        let h1 = blake3_hash_parallel(data1);
        let h2 = blake3_hash_parallel(data2);
        assert_ne!(h1, h2, "different inputs must produce different hashes");
    }

    #[test]
    fn test_blake3_file_hash() -> io::Result<()> {
        let mut tmp = NamedTempFile::new()?;
        let data = b"arc test file content for hashing";
        tmp.write_all(data)?;
        tmp.flush()?;

        let file_hash = blake3_hash_file(tmp.path())?;
        let data_hash = blake3_hash_parallel(data);
        assert_eq!(file_hash, data_hash, "file hash must match data hash");
        Ok(())
    }

    #[test]
    fn test_arc_fast_hash_small_file() -> io::Result<()> {
        let mut tmp = NamedTempFile::new()?;
        tmp.write_all(b"small file")?;
        tmp.flush()?;

        let h1 = arc_fast_hash(tmp.path())?;
        let h2 = arc_fast_hash(tmp.path())?;
        assert_eq!(h1, h2, "fast hash must be deterministic");
        Ok(())
    }

    #[test]
    fn test_merkle_tree_roundtrip() {
        let data = b"hello world, this is a test chunk of data for the merkle tree";
        let chunk_size = 16;
        let tree = MerkleTree::build(data, chunk_size);

        // Every chunk must verify
        for (i, chunk) in data.chunks(chunk_size).enumerate() {
            assert!(
                tree.verify_chunk(i, chunk),
                "chunk {i} must verify against Merkle tree"
            );
        }

        // Wrong data must fail
        let bad_chunk = b"XXXXXXXXXXXXXXXX";
        assert!(
            !tree.verify_chunk(0, bad_chunk),
            "wrong chunk must fail verification"
        );
    }

    #[test]
    fn test_merkle_tree_single_chunk() {
        let data = b"single chunk";
        let tree = MerkleTree::build(data, 1024);
        assert_eq!(tree.leaf_count(), 1);
        assert!(tree.verify_chunk(0, data));
    }

    #[test]
    fn test_merkle_tree_empty() {
        let tree = MerkleTree::build(&[], 1024);
        assert_eq!(tree.leaf_count(), 1); // empty file = one empty leaf
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let data = vec![0x55u8; 1024];
        let tree1 = MerkleTree::build(&data, 256);
        let tree2 = MerkleTree::build(&data, 256);
        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_merkle_different_files_different_roots() {
        let data1 = vec![0x00u8; 1024];
        let data2 = vec![0xFFu8; 1024];
        let tree1 = MerkleTree::build(&data1, 256);
        let tree2 = MerkleTree::build(&data2, 256);
        assert_ne!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_merkle_proof_generation_and_verification() {
        let data = vec![0xAAu8; 4 * 256]; // 4 chunks of 256 bytes
        let tree = MerkleTree::build(&data, 256);
        let root = tree.root();

        for i in 0..4 {
            let chunk = &data[i * 256..(i + 1) * 256];
            let proof = tree.proof(i);
            
            // Verify using direct method
            assert!(tree.verify_chunk(i, chunk));
            
            // Verify using proof method
            assert!(MerkleTree::verify_with_proof(&root, i, 4, chunk, &proof));

            // Verify with bad chunk fails
            let mut bad_chunk = chunk.to_vec();
            bad_chunk[0] ^= 0xFF;
            assert!(!MerkleTree::verify_with_proof(&root, i, 4, &bad_chunk, &proof));

            // Verify with truncated/invalid proof length fails
            if !proof.is_empty() {
                let truncated_proof = &proof[..proof.len() - 1];
                assert!(!MerkleTree::verify_with_proof(&root, i, 4, chunk, truncated_proof));
            }
        }

        // Root must be consistent
        let root2 = tree.root();
        assert_eq!(root, root2);
    }

    #[test]
    fn test_blake3_hash_dir_deterministic() {
        use tempfile::tempdir;
        use std::fs::File;
        use std::io::Write;
        
        let dir = tempdir().unwrap();
        let file_path1 = dir.path().join("a.txt");
        let file_path2 = dir.path().join("b.txt");
        
        let mut f1 = File::create(&file_path1).unwrap();
        f1.write_all(b"content a").unwrap();
        
        let mut f2 = File::create(&file_path2).unwrap();
        f2.write_all(b"content b").unwrap();
        
        let hash1 = blake3_hash_dir(dir.path()).unwrap();
        let hash2 = blake3_hash_dir(dir.path()).unwrap();
        assert_eq!(hash1, hash2, "hashing same directory must be deterministic");
        
        // Changing content must change hash
        let mut f1_mod = File::create(&file_path1).unwrap();
        f1_mod.write_all(b"content a changed").unwrap();
        let hash3 = blake3_hash_dir(dir.path()).unwrap();
        assert_ne!(hash1, hash3, "changing content must change hash");
    }
}
