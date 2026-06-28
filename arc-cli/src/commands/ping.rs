use arc_core::transfer::orchestrator::ping_peer;

pub async fn exec_ping(device: String) -> anyhow::Result<()> {
    println!("Pinging device {}...", device);
    match ping_peer(&device).await {
        Ok(rtt) => {
            println!(
                "Ping response from {}: Reachable (RTT: {:.1}ms)",
                device,
                rtt.as_secs_f32() * 1000.0
            );
        }
        Err(e) => {
            println!("Failed to ping device {}: {}", device, e);
            std::process::exit(1);
        }
    }
    Ok(())
}
