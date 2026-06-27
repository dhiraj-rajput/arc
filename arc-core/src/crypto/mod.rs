//! Cryptographic primitives for arc.
//!
//! Modules:
//! - `cipher`: Symmetric encryption (ChaCha20-Poly1305 / AES-256-GCM)
//! - `hash`: BLAKE3 parallel hashing, Merkle tree, fast dedup probe
//! - `identity`: Ed25519 device identity and X25519 session key exchange

pub mod cipher;
pub mod hash;
pub mod identity;

pub use cipher::{CipherSuite, decrypt_chunk, encrypt_chunk};
pub use hash::{arc_fast_hash, blake3_hash_parallel, MerkleTree};
pub use identity::{DeviceIdentity, SessionKeys, derive_key_from_phrase};
