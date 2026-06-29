use crate::PeersCommands;
use arc_core::get_identity_with_merged_config;
use arc_core::storage::save_config;

pub async fn exec_peers(cmd: PeersCommands) -> anyhow::Result<()> {
    let (_, mut config) = get_identity_with_merged_config()?;
    match cmd {
        PeersCommands::List => {
            if config.peers.is_empty() {
                println!("No paired devices found. Use 'arc pair' to pair a new device.");
            } else {
                println!("Paired Devices ({}):", config.peers.len());
                for peer in &config.peers {
                    println!("  - {} (ID: {})", peer.name, hex::encode(peer.device_id));
                }
            }
        }
        PeersCommands::Show { name } => {
            if let Some(peer) = config.peers.iter().find(|p| p.name == name) {
                println!("Device Name: {}", peer.name);
                println!("Device ID:   {}", hex::encode(peer.device_id));
            } else {
                println!("Device not found: {}", name);
            }
        }
        PeersCommands::Revoke { name } => {
            if let Some(pos) = config.peers.iter().position(|p| p.name == name) {
                config.peers.remove(pos);
                save_config(&config)?;
                println!("Revoked access from device: {}", name);
            } else {
                println!("Device not found: {}", name);
            }
        }
    }
    Ok(())
}
