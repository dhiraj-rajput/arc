use arc_core::transfer::DiscoveryManager;
use std::time::Duration;

pub async fn exec_discover() -> Result<(), anyhow::Error> {
    println!("Scanning local network for active arc devices (mDNS)...");
    let manager = DiscoveryManager::new()?;

    // Resolve for 3 seconds
    let peers = manager.discover_detailed_peers(Duration::from_secs(3));

    if peers.is_empty() {
        println!("No arc devices found on the local network.");
        return Ok(());
    }

    println!("\nDiscovered Devices:");
    println!(
        "{:<25} {:<25} {:<15}",
        "Device Name", "IP Address", "Device ID (Prefix)"
    );
    println!("{}", "-".repeat(70));
    for (name, addr, device_id) in peers {
        let display_id = if device_id.len() >= 8 {
            &device_id[..8]
        } else {
            &device_id
        };
        println!("{:<25} {:<25} {:<15}", name, addr.to_string(), display_id);
    }
    println!();
    Ok(())
}
