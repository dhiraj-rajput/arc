use crate::ConfigCommands;
use arc_core::get_identity_with_merged_config;
use arc_core::storage::save_config;

pub async fn exec_config(cmd: ConfigCommands) -> anyhow::Result<()> {
    let (identity, mut config) = get_identity_with_merged_config()?;
    match cmd {
        ConfigCommands::Show => {
            print_config_details(&identity, &config);
        }
        ConfigCommands::Get { key } => match key.as_str() {
            "device_name" => println!("{}", config.device_name),
            "relay_url" => println!("{}", config.relay_url),
            "max_upload_mbps" => match config.max_upload_mbps {
                Some(val) => println!("{}", val),
                None => println!("None"),
            },
            "dns_probe_ipv4" => println!("{}", config.dns_probe_ipv4),
            "dns_probe_ipv6" => println!("{}", config.dns_probe_ipv6),
            "quic_connect_timeout_ms" => println!("{}", config.transport.quic_connect_timeout_ms),
            "p2p_racing_timeout_ms" => println!("{}", config.transport.p2p_racing_timeout_ms),
            "mdns_browse_timeout_ms" => println!("{}", config.transport.mdns_browse_timeout_ms),
            _ => println!(
                "Unknown config key: {}. Valid keys: device_name, relay_url, max_upload_mbps, dns_probe_ipv4, dns_probe_ipv6, quic_connect_timeout_ms, p2p_racing_timeout_ms, mdns_browse_timeout_ms",
                key
            ),
        },
        ConfigCommands::Set { key, value } => {
            match key.as_str() {
                "device_name" => {
                    config.device_name = value;
                }
                "relay_url" => {
                    config.relay_url = value;
                }
                "max_upload_mbps" => {
                    if value.to_lowercase() == "none" {
                        config.max_upload_mbps = None;
                    } else {
                        let mbps: u32 = value.parse().map_err(|e| {
                            anyhow::anyhow!("Invalid integer for max_upload_mbps: {}", e)
                        })?;
                        config.max_upload_mbps = Some(mbps);
                    }
                }
                "dns_probe_ipv4" => {
                    config.dns_probe_ipv4 = value;
                }
                "dns_probe_ipv6" => {
                    config.dns_probe_ipv6 = value;
                }
                "quic_connect_timeout_ms" => {
                    let ms: u64 = value.parse().map_err(|e| {
                        anyhow::anyhow!("Invalid integer for quic_connect_timeout_ms: {}", e)
                    })?;
                    config.transport.quic_connect_timeout_ms = ms;
                }
                "p2p_racing_timeout_ms" => {
                    let ms: u64 = value.parse().map_err(|e| {
                        anyhow::anyhow!("Invalid integer for p2p_racing_timeout_ms: {}", e)
                    })?;
                    config.transport.p2p_racing_timeout_ms = ms;
                }
                "mdns_browse_timeout_ms" => {
                    let ms: u64 = value.parse().map_err(|e| {
                        anyhow::anyhow!("Invalid integer for mdns_browse_timeout_ms: {}", e)
                    })?;
                    config.transport.mdns_browse_timeout_ms = ms;
                }
                _ => {
                    return Err(anyhow::anyhow!(
                        "Unknown configuration key: '{}'. Valid keys: device_name, relay_url, max_upload_mbps, dns_probe_ipv4, dns_probe_ipv6, quic_connect_timeout_ms, p2p_racing_timeout_ms, mdns_browse_timeout_ms",
                        key
                    ));
                }
            }
            save_config(&config)?;
            println!("Successfully set '{}' and saved configuration.", key);
        }
    }
    Ok(())
}

fn print_config_details(
    identity: &arc_core::crypto::identity::DeviceIdentity,
    config: &arc_core::ArcConfig,
) {
    println!("Device configuration:");
    println!("  device_name:             {}", config.device_name);
    println!(
        "  device_id:               {}",
        hex::encode(identity.device_id())
    );
    println!("  relay_url:               {}", config.relay_url);
    println!(
        "  max_upload_mbps:         {}",
        config
            .max_upload_mbps
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unlimited".to_string())
    );
    println!("  dns_probe_ipv4:          {}", config.dns_probe_ipv4);
    println!("  dns_probe_ipv6:          {}", config.dns_probe_ipv6);
    println!(
        "  quic_connect_timeout_ms: {}",
        config.transport.quic_connect_timeout_ms
    );
    println!(
        "  p2p_racing_timeout_ms:   {}",
        config.transport.p2p_racing_timeout_ms
    );
    println!(
        "  mdns_browse_timeout_ms:  {}",
        config.transport.mdns_browse_timeout_ms
    );
    println!("  paired_devices:          {}", config.peers.len());
    let keyring_status = if arc_core::keystore::get_identity_secret().is_ok() {
        "OS keyring (secure)"
    } else {
        "config file (fallback)"
    };
    println!("  identity_storage:        {}", keyring_status);
}
