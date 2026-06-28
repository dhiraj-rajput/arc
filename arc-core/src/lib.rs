//! arc-core: Core library for the arc secure P2P file and clipboard transfer tool.
//!
//! # Architecture
//! - `machine`: Runtime machine capacity detection (CPU, RAM, AES-NI)
//! - `crypto`: Identity keys, session keys, encryption, BLAKE3 hashing
//! - `compression`: Adaptive zstd/lz4 compression with compressibility probing
//! - `protocol`: Wire protocol types, state machine, TLV capabilities
//! - `transfer`: Adaptive chunking, pipeline, resume logic, clipboard sync
//! - `security`: Filename sanitization, path validation, security invariants
//! - `config`: Layered configuration loading (defaults < file < env < CLI)

pub mod compression;
pub mod crypto;
pub mod machine;
pub mod protocol;
pub mod security;
pub mod transfer;
pub mod storage;
pub mod keystore;
pub mod config;

// Re-export the most commonly used types
pub use machine::MachineCapacity;
pub use protocol::messages::ArcMessage;
pub use security::{safe_display_name, validate_path_component, safe_unpack_tar, SandboxPolicy};
pub use storage::{get_or_create_identity, load_config, save_config, wipe_config, ArcConfig, PeerInfo, TransferHistoryEntry, add_transfer_history, get_transfer_history, get_db_conn, get_db_path, ENV_CONFIG_DIR};
pub use config::{load_merged_config, get_identity_with_merged_config};
pub use crypto::hash::{blake3_hash_file, blake3_hash_dir};
