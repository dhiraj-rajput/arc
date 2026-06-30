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
pub mod config;
pub mod crypto;
pub mod keystore;
pub mod machine;
pub mod protocol;
pub mod security;
pub mod storage;
pub mod transfer;

// Re-export the most commonly used types
pub use config::{get_identity_with_merged_config, load_merged_config};
pub use crypto::hash::{blake3_hash_dir, blake3_hash_file};
pub use machine::MachineCapacity;
pub use protocol::messages::ArcMessage;
pub use security::{SandboxPolicy, safe_display_name, safe_unpack_tar, validate_path_component};
pub use storage::{
    ArcConfig, ENV_CONFIG_DIR, PeerInfo, TransferHistoryEntry, add_transfer_history, get_db_conn,
    get_db_path, get_or_create_identity, get_transfer_history, load_config, save_config,
    wipe_config,
};

/// Connect to a WebSocket relay.
pub async fn connect_relay(
    url_str: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    anyhow::Error,
> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    use tokio_tungstenite::connect_async;
    let mut attempts = 0;
    let max_attempts = 3;

    loop {
        attempts += 1;
        match connect_async(url_str).await {
            Ok((ws_stream, _)) => return Ok(ws_stream),
            Err(e) => {
                if attempts >= max_attempts {
                    return Err(anyhow::anyhow!(
                        "Failed to connect to relay after {} attempts: {}",
                        max_attempts,
                        e
                    ));
                }
                println!(
                    "⚠️ Relay connection attempt {} failed ({}). Retrying in 1s...",
                    attempts, e
                );
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
}
