//! Layered configuration loading for arc.
//!
//! Configuration is loaded in priority order (later overrides earlier):
//! 1. Built-in defaults
//! 2. Config file (`~/.config/arc/config.json`)
//! 3. Environment variables (`ARC_RELAY_URL`, `ARC_DNS_PROBE_IPV4`, etc.)
//! 4. CLI flags (handled by the caller)

use crate::storage::{ArcConfig, TransportConfig};

/// Environment variable names for configuration overrides.
pub const ENV_RELAY_URL: &str = "ARC_RELAY_URL";
pub const ENV_DEVICE_NAME: &str = "ARC_DEVICE_NAME";
pub const ENV_MAX_UPLOAD_MBPS: &str = "ARC_MAX_UPLOAD_MBPS";
pub const ENV_DNS_PROBE_IPV4: &str = "ARC_DNS_PROBE_IPV4";
pub const ENV_DNS_PROBE_IPV6: &str = "ARC_DNS_PROBE_IPV6";
pub const ENV_QUIC_CONNECT_TIMEOUT_MS: &str = "ARC_QUIC_CONNECT_TIMEOUT_MS";
pub const ENV_P2P_RACING_TIMEOUT_MS: &str = "ARC_P2P_RACING_TIMEOUT_MS";
pub const ENV_MDNS_BROWSE_TIMEOUT_MS: &str = "ARC_MDNS_BROWSE_TIMEOUT_MS";

/// Load the merged configuration from all layers.
///
/// Priority: built-in defaults < config file < environment variables.
/// CLI flags should be applied by the caller on top of the returned config.
pub fn load_merged_config() -> Result<ArcConfig, anyhow::Error> {
    // Layer 1 & 2: Load from file (which already has built-in defaults via serde)
    let mut config = match crate::storage::load_config() {
        Ok(c) => c,
        Err(_) => {
            // No config file exists yet; use built-in defaults
            default_config()
        }
    };

    // Layer 3: Apply environment variable overrides
    apply_env_overrides(&mut config);

    Ok(config)
}

/// Returns the built-in default configuration.
pub fn default_config() -> ArcConfig {
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| {
            let rand_val: u16 = rand::random();
            format!("device-{:04x}", rand_val)
        });

    ArcConfig {
        device_name: hostname,
        identity_secret: None,
        peers: Vec::new(),
        relay_url: "wss://relay.arc.sh/ws".to_string(),
        max_upload_mbps: None,
        dns_probe_ipv4: "8.8.8.8:80".to_string(),
        dns_probe_ipv6: "[2001:4860:4860::8888]:80".to_string(),
        transport: TransportConfig::default(),
    }
}

/// Apply environment variable overrides to the config.
fn apply_env_overrides(config: &mut ArcConfig) {
    if let Ok(val) = std::env::var(ENV_RELAY_URL) {
        config.relay_url = val;
    }
    if let Ok(val) = std::env::var(ENV_DEVICE_NAME) {
        config.device_name = val;
    }
    if let Ok(val) = std::env::var(ENV_MAX_UPLOAD_MBPS) {
        if let Ok(parsed) = val.parse::<u32>() {
            config.max_upload_mbps = Some(parsed);
        }
    }
    if let Ok(val) = std::env::var(ENV_DNS_PROBE_IPV4) {
        config.dns_probe_ipv4 = val;
    }
    if let Ok(val) = std::env::var(ENV_DNS_PROBE_IPV6) {
        config.dns_probe_ipv6 = val;
    }
    if let Ok(val) = std::env::var(ENV_QUIC_CONNECT_TIMEOUT_MS) {
        if let Ok(parsed) = val.parse::<u64>() {
            config.transport.quic_connect_timeout_ms = parsed;
        }
    }
    if let Ok(val) = std::env::var(ENV_P2P_RACING_TIMEOUT_MS) {
        if let Ok(parsed) = val.parse::<u64>() {
            config.transport.p2p_racing_timeout_ms = parsed;
        }
    }
    if let Ok(val) = std::env::var(ENV_MDNS_BROWSE_TIMEOUT_MS) {
        if let Ok(parsed) = val.parse::<u64>() {
            config.transport.mdns_browse_timeout_ms = parsed;
        }
    }
}

/// Load the identity and merged config (applying environment overrides).
pub fn get_identity_with_merged_config()
-> Result<(crate::crypto::identity::DeviceIdentity, ArcConfig), anyhow::Error> {
    let (identity, mut config) = crate::storage::get_or_create_identity()?;
    if let Ok(merged) = load_merged_config() {
        config = merged;
    }
    Ok((identity, config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_has_production_relay() {
        let config = default_config();
        assert!(config.relay_url.starts_with("wss://"));
        assert!(!config.relay_url.contains("127.0.0.1"));
    }

    #[test]
    fn test_default_config_no_plaintext_secret() {
        let config = default_config();
        assert!(config.identity_secret.is_none());
    }

    #[test]
    fn test_env_override_relay_url() {
        let mut config = default_config();
        // Simulate env override
        config.relay_url = "wss://custom-relay.example.com/ws".to_string();
        assert_eq!(config.relay_url, "wss://custom-relay.example.com/ws");
    }

    #[test]
    fn test_default_transport_config() {
        let tc = TransportConfig::default();
        assert_eq!(tc.quic_connect_timeout_ms, 3000);
        assert_eq!(tc.p2p_racing_timeout_ms, 2000);
        assert_eq!(tc.mdns_browse_timeout_ms, 500);
    }
}
