//! Local storage for device identity and paired peers configuration.

use std::fs;
use std::path::PathBuf;
use crate::crypto::identity::DeviceIdentity;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerInfo {
    pub name: String,
    pub device_id: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ArcConfig {
    pub device_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_secret: Option<[u8; 32]>,
    #[serde(skip)]
    pub peers: Vec<PeerInfo>,
    pub relay_url: String,
    #[serde(default)]
    pub max_upload_mbps: Option<u32>,
    #[serde(default = "default_dns_probe_ipv4")]
    pub dns_probe_ipv4: String,
    #[serde(default = "default_dns_probe_ipv6")]
    pub dns_probe_ipv6: String,
    #[serde(default)]
    pub transport: TransportConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransportConfig {
    #[serde(default = "default_quic_connect_timeout_ms")]
    pub quic_connect_timeout_ms: u64,
    #[serde(default = "default_p2p_racing_timeout_ms")]
    pub p2p_racing_timeout_ms: u64,
    #[serde(default = "default_mdns_browse_timeout_ms")]
    pub mdns_browse_timeout_ms: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            quic_connect_timeout_ms: default_quic_connect_timeout_ms(),
            p2p_racing_timeout_ms: default_p2p_racing_timeout_ms(),
            mdns_browse_timeout_ms: default_mdns_browse_timeout_ms(),
        }
    }
}

fn default_quic_connect_timeout_ms() -> u64 {
    3000
}
fn default_p2p_racing_timeout_ms() -> u64 {
    2000
}
fn default_mdns_browse_timeout_ms() -> u64 {
    500
}

fn default_dns_probe_ipv4() -> String {
    "8.8.8.8:80".to_string()
}

fn default_dns_probe_ipv6() -> String {
    "[2001:4860:4860::8888]:80".to_string()
}

/// Returns the configuration file path using `dirs::config_dir()`
pub fn get_config_path() -> PathBuf {
    let mut p = dirs::config_dir().unwrap_or_else(|| {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        let mut path = PathBuf::from(home);
        path.push(".config");
        path
    });
    p.push("arc");
    p.push("config.json");
    p
}

/// Load configuration from disk.
pub fn load_config() -> Result<ArcConfig, anyhow::Error> {
    let path = get_config_path();
    let content = fs::read_to_string(&path)?;
    let mut config: ArcConfig = serde_json::from_str(&content)?;
    
    // Load peers from SQLite
    if let Ok(conn) = get_db_conn() {
        let mut stmt = conn.prepare("SELECT device_id, name FROM peers")?;
        let peer_iter = stmt.query_map([], |row| {
            let device_id_bytes: Vec<u8> = row.get(0)?;
            let mut device_id = [0u8; 32];
            device_id.copy_from_slice(&device_id_bytes);
            Ok(PeerInfo {
                name: row.get(1)?,
                device_id,
            })
        })?;
        
        let mut peers = Vec::new();
        for peer in peer_iter {
            peers.push(peer?);
        }
        config.peers = peers;
    }
    
    Ok(config)
}

/// Save configuration to disk. Enforces secure 0o600 permissions on Unix.
pub fn save_config(config: &ArcConfig) -> Result<(), anyhow::Error> {
    let path = get_config_path();
    let parent = path.parent().ok_or_else(|| anyhow::anyhow!("no parent directory for config path"))?;
    fs::create_dir_all(parent)?;
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(parent)?.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(parent, perms)?;
    }

    let content = serde_json::to_string_pretty(config)?;
    
    // Create a temp file in the same directory to guarantee atomic rename is on same filesystem device
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = temp.as_file().metadata()?.permissions();
        perms.set_mode(0o600);
        temp.as_file().set_permissions(perms)?;
    }

    use std::io::Write;
    temp.write_all(content.as_bytes())?;
    temp.as_file().sync_all()?;
    
    // Atomically persist to target path
    temp.persist(&path)?;

    // Save peers to SQLite
    if let Ok(conn) = get_db_conn() {
        conn.execute("DELETE FROM peers", [])?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let mut stmt = conn.prepare("INSERT OR REPLACE INTO peers (device_id, name, paired_at) VALUES (?, ?, ?)")?;
        for peer in &config.peers {
            stmt.execute(rusqlite::params![&peer.device_id.to_vec(), &peer.name, now])?;
        }
    }

    #[cfg(windows)]
    {
        if let Ok(username) = std::env::var("USERNAME") {
            match std::process::Command::new("icacls")
                .arg(&path)
                .arg("/inheritance:r")
                .arg("/grant:r")
                .arg(format!("{}:(F)", username))
                .status()
            {
                Ok(status) => {
                    if !status.success() {
                        tracing::warn!("icacls failed to set file permissions on {:?}", path);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to execute icacls command to restrict file permissions on {:?}: {:?}", path, e);
                }
            }
        } else {
            tracing::warn!("USERNAME environment variable not set; skipping icacls configuration on {:?}", path);
        }
    }
    Ok(())
}

/// Wipe all pairing keys, configuration, and keyring secrets.
pub fn wipe_config() -> Result<(), anyhow::Error> {
    let path = get_config_path();
    if path.exists() {
        fs::remove_file(path)?;
    }
    let db_path = get_db_path();
    if db_path.exists() {
        fs::remove_file(db_path)?;
    }
    let _ = crate::keystore::delete_identity_secret();
    Ok(())
}

tokio::task_local! {
    pub static TEST_IDENTITY: [u8; 32];
}

pub fn get_or_create_identity() -> Result<(DeviceIdentity, ArcConfig), anyhow::Error> {
    let (mut identity, config) = get_or_create_identity_internal()?;
    if let Some(secret) = TEST_IDENTITY.try_with(|s| *s).ok() {
        identity = DeviceIdentity::from_secret_bytes(&secret);
    }
    Ok((identity, config))
}

fn get_or_create_identity_internal() -> Result<(DeviceIdentity, ArcConfig), anyhow::Error> {
    let path = get_config_path();
    let secret_from_keystore = crate::keystore::get_identity_secret().ok();

    if path.exists() {
        let mut config = load_config()?;
        let secret = match secret_from_keystore {
            Some(s) => {
                if config.identity_secret.is_some() {
                    config.identity_secret = None;
                    save_config(&config)?;
                }
                s
            }
            None => {
                match config.identity_secret {
                    Some(s) => {
                        if crate::keystore::set_identity_secret(&s).is_ok() {
                            config.identity_secret = None;
                            save_config(&config)?;
                        }
                        s
                    }
                    None => {
                        let identity = DeviceIdentity::generate();
                        let s = identity.secret_bytes();
                        if crate::keystore::set_identity_secret(&s).is_err() {
                            config.identity_secret = Some(s);
                        }
                        save_config(&config)?;
                        s
                    }
                }
            }
        };

        let identity = DeviceIdentity::from_secret_bytes(&secret);
        Ok((identity, config))
    } else {
        let secret = match secret_from_keystore {
            Some(s) => s,
            None => {
                let identity = DeviceIdentity::generate();
                let s = identity.secret_bytes();
                if crate::keystore::set_identity_secret(&s).is_err() {
                    Some(s)
                } else {
                    None
                }
                .unwrap_or(s)
            }
        };

        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| {
                let rand_val: u16 = rand::random();
                format!("device-{:04x}", rand_val)
            });

        let has_keyring = crate::keystore::get_identity_secret().is_ok();
        let config_secret = if has_keyring { None } else { Some(secret) };

        let config = ArcConfig {
            device_name: hostname,
            identity_secret: config_secret,
            peers: Vec::new(),
            relay_url: "wss://relay.arc.sh/ws".to_string(),
            max_upload_mbps: None,
            dns_probe_ipv4: default_dns_probe_ipv4(),
            dns_probe_ipv6: default_dns_probe_ipv6(),
            transport: TransportConfig::default(),
        };
        save_config(&config)?;
        let identity = DeviceIdentity::from_secret_bytes(&secret);
        Ok((identity, config))
    }
}

// ─── SQLite DB APIs ───────────────────────────────────────────────────────────

/// Returns the SQLite database file path.
#[cfg(not(test))]
pub fn get_db_path() -> PathBuf {
    let mut p = dirs::config_dir().unwrap_or_else(|| {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| ".".to_string());
        let mut path = PathBuf::from(home);
        path.push(".config");
        path
    });
    p.push("arc");
    p.push("arc.db");
    p
}

/// Returns a unique temporary SQLite database file path for unit tests.
#[cfg(test)]
pub fn get_db_path() -> PathBuf {
    thread_local! {
        static TEST_DB_PATH: PathBuf = {
            let mut p = std::env::temp_dir();
            p.push(format!("arc_test_{}.db", uuid::Uuid::new_v4()));
            p
        };
    }
    TEST_DB_PATH.with(|p| p.clone())
}

/// Get a connection to the SQLite database and initialize tables if needed.
pub fn get_db_conn() -> Result<rusqlite::Connection, anyhow::Error> {
    let path = get_db_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let conn = rusqlite::Connection::open(&path)?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS peers (
            device_id BLOB PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            paired_at INTEGER NOT NULL
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS transfer_history (
            transfer_id BLOB PRIMARY KEY,
            kind TEXT NOT NULL,
            file_name TEXT NOT NULL,
            total_size INTEGER NOT NULL,
            peer_device_id BLOB NOT NULL,
            direction TEXT NOT NULL,
            completed_at INTEGER NOT NULL,
            status TEXT NOT NULL
        )",
        [],
    )?;

    Ok(conn)
}

/// Represents a transfer history entry stored in SQLite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferHistoryEntry {
    pub transfer_id: [u8; 16],
    pub kind: String,
    pub file_name: String,
    pub total_size: u64,
    pub peer_device_id: [u8; 32],
    pub direction: String,
    pub completed_at: u64,
    pub status: String,
}

/// Add a new transfer entry to the history database.
pub fn add_transfer_history(entry: &TransferHistoryEntry) -> Result<(), anyhow::Error> {
    let conn = get_db_conn()?;
    conn.execute(
        "INSERT INTO transfer_history (transfer_id, kind, file_name, total_size, peer_device_id, direction, completed_at, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        rusqlite::params![
            &entry.transfer_id.to_vec(),
            &entry.kind,
            &entry.file_name,
            &entry.total_size,
            &entry.peer_device_id.to_vec(),
            &entry.direction,
            &entry.completed_at,
            &entry.status
        ],
    )?;
    Ok(())
}

/// Retrieve all transfer history entries sorted by completion time (newest first).
pub fn get_transfer_history() -> Result<Vec<TransferHistoryEntry>, anyhow::Error> {
    let conn = get_db_conn()?;
    let mut stmt = conn.prepare(
        "SELECT transfer_id, kind, file_name, total_size, peer_device_id, direction, completed_at, status FROM transfer_history ORDER BY completed_at DESC"
    )?;
    let history_iter = stmt.query_map([], |row| {
        let tid_bytes: Vec<u8> = row.get(0)?;
        let mut transfer_id = [0u8; 16];
        transfer_id.copy_from_slice(&tid_bytes);
        
        let pid_bytes: Vec<u8> = row.get(4)?;
        let mut peer_device_id = [0u8; 32];
        peer_device_id.copy_from_slice(&pid_bytes);

        Ok(TransferHistoryEntry {
            transfer_id,
            kind: row.get(1)?,
            file_name: row.get(2)?,
            total_size: row.get(3)?,
            peer_device_id,
            direction: row.get(5)?,
            completed_at: row.get(6)?,
            status: row.get(7)?,
        })
    })?;

    let mut entries = Vec::new();
    for entry in history_iter {
        entries.push(entry?);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqlite_db_init_and_peers() {
        let _conn = get_db_conn().expect("failed to connect to test db");
        
        let peer = PeerInfo {
            name: "test_device".to_string(),
            device_id: [0x55; 32],
        };
        
        let config = ArcConfig {
            device_name: "test_host".to_string(),
            identity_secret: None,
            peers: vec![peer.clone()],
            relay_url: "wss://relay".to_string(),
            max_upload_mbps: None,
            dns_probe_ipv4: "8.8.8.8".to_string(),
            dns_probe_ipv6: "::1".to_string(),
            transport: Default::default(),
        };

        save_config(&config).expect("failed to save config");
        
        let loaded = load_config().expect("failed to load config");
        assert_eq!(loaded.peers.len(), 1);
        assert_eq!(loaded.peers[0].name, "test_device");
        assert_eq!(loaded.peers[0].device_id, [0x55; 32]);

        let db_path = get_db_path();
        if db_path.exists() {
            let _ = std::fs::remove_file(db_path);
        }
    }

    #[test]
    fn test_sqlite_transfer_history() {
        let entry = TransferHistoryEntry {
            transfer_id: [0xAA; 16],
            kind: "File".to_string(),
            file_name: "test.txt".to_string(),
            total_size: 1024,
            peer_device_id: [0x77; 32],
            direction: "Sent".to_string(),
            completed_at: 123456789,
            status: "Completed".to_string(),
        };

        add_transfer_history(&entry).expect("failed to add transfer history");
        
        let history = get_transfer_history().expect("failed to get history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].transfer_id, [0xAA; 16]);
        assert_eq!(history[0].file_name, "test.txt");
        assert_eq!(history[0].total_size, 1024);
        assert_eq!(history[0].status, "Completed");

        let db_path = get_db_path();
        if db_path.exists() {
            let _ = std::fs::remove_file(db_path);
        }
    }
}
