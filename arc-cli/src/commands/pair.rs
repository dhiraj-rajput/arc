use arc_core::get_identity_with_merged_config;
use arc_core::transfer::orchestrator::{run_pairing_sender, run_pairing_receiver};
use crate::generate_phrase;

pub async fn exec_pair(
    name: Option<String>,
    relay_override: Option<String>,
) -> anyhow::Result<()> {
    let (_, config) = get_identity_with_merged_config()?;
    let relay_url = relay_override.as_deref().unwrap_or(&config.relay_url);
    let display_name = name.unwrap_or_else(|| config.device_name.clone());
    
    let selections = &["1) Initiator (Show pairing code)", "2) Joiner (Enter pairing code)"];
    let selection = dialoguer::Select::with_theme(&dialoguer::theme::SimpleTheme)
        .with_prompt("Choose pairing role")
        .items(selections)
        .default(0)
        .interact()?;

    if selection == 0 {
        let code = generate_phrase();
        println!("\nPairing Initiated!");
        println!("==================");
        println!("Provide this membrane pairing code to your other device:");
        println!("\n    👉 \x1b[1;36m{}\x1b[0m 👈\n", code);
        println!("Waiting for the other device to connect and authenticate...");

        // Generate dynamic QR code for pairing
        if let Ok(code_obj) = qrcode::QrCode::new(code.as_bytes()) {
            let image = code_obj
                .render::<qrcode::render::unicode::Dense1x2>()
                .dark_color(qrcode::render::unicode::Dense1x2::Light)
                .light_color(qrcode::render::unicode::Dense1x2::Dark)
                .build();
            println!("You can also scan this QR code on the other device:");
            println!("{}", image);
        }

        run_pairing_sender(&display_name, &code, relay_url).await?;
        println!("\n🎉 Pairing completed successfully! Device '{}' is now authorized.", display_name);
    } else {
        let code = dialoguer::Input::<String>::with_theme(&dialoguer::theme::SimpleTheme)
            .with_prompt("Enter the pairing code from the other device")
            .interact_text()?;

        println!("\nPairing Joiner!");
        println!("===============");
        println!("Connecting to relay and authenticating identity keys...");

        run_pairing_receiver(&display_name, &code, relay_url).await?;
        println!("\n🎉 Pairing completed successfully! Device '{}' is now authorized.", display_name);
    }
    Ok(())
}
