use arc_core::get_identity_with_merged_config;
use arc_core::transfer::orchestrator::check_relay_status;

pub async fn exec_relay(relay_override: Option<String>) -> anyhow::Result<()> {
    let (_, config) = get_identity_with_merged_config()?;
    let url = relay_override.as_deref().unwrap_or(&config.relay_url);
    println!("Checking connection and latency to relay {}...", url);
    match check_relay_status(url).await {
        Ok(latency) => {
            println!("  ✅ Relay is ONLINE (Latency: {}ms)", latency.as_millis());
        }
        Err(e) => {
            println!("  ❌ Relay is OFFLINE or unreachable: {}", e);
        }
    }
    Ok(())
}
