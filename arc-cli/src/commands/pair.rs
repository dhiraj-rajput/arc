use crate::ui::generate_phrase;
use arc_core::get_identity_with_merged_config;
use arc_core::transfer::orchestrator::{run_pairing_receiver, run_pairing_sender};

pub async fn exec_pair(
    name: Option<String>,
    initiator: bool,
    code: Option<String>,
    joiner: Option<String>,
    relay_override: Option<String>,
) -> anyhow::Result<()> {
    let (_, config) = get_identity_with_merged_config()?;
    let relay_url = relay_override.as_deref().unwrap_or(&config.relay_url);
    let display_name = name.unwrap_or_else(|| config.device_name.clone());

    let is_initiator = if initiator {
        true
    } else if joiner.is_some() {
        false
    } else {
        let selections = &[
            "1) Initiator (Show pairing code)",
            "2) Joiner (Enter pairing code)",
        ];
        let selection = dialoguer::Select::with_theme(&dialoguer::theme::SimpleTheme)
            .with_prompt("Choose pairing role")
            .items(selections)
            .default(0)
            .interact()?;
        selection == 0
    };

    if is_initiator {
        let pairing_code = code.unwrap_or_else(generate_phrase);
        println!("\nPairing initiated");
        println!("================");
        println!("Provide this membrane pairing code to your other device:");
        println!("\n    {}\n", pairing_code);
        println!(
            "Membrane pairing code generated. Waiting for the other device to connect and authenticate..."
        );

        // Generate dynamic QR code for pairing
        if let Ok(code_obj) = qrcode::QrCode::new(pairing_code.as_bytes()) {
            let image = code_obj
                .render::<qrcode::render::unicode::Dense1x2>()
                .dark_color(qrcode::render::unicode::Dense1x2::Light)
                .light_color(qrcode::render::unicode::Dense1x2::Dark)
                .build();
            println!("You can also scan this QR code on the other device:");
            println!("{}", image);
        }

        println!("Connecting to relay and listening for connection...");
        let (peer_id, peer_name) =
            run_pairing_sender(&pairing_code, relay_url, &display_name).await?;
        handle_approval_and_save(peer_id, peer_name).await?;
    } else {
        let code = if let Some(code_val) = joiner {
            code_val
        } else {
            dialoguer::Input::<String>::with_theme(&dialoguer::theme::SimpleTheme)
                .with_prompt("Enter the pairing code from the other device")
                .interact_text()?
        };

        println!("\nPairing joiner");
        println!("===============");
        println!("Connecting to relay and authenticating identity keys...");

        let (peer_id, peer_name) = run_pairing_receiver(&code, relay_url, &display_name).await?;
        handle_approval_and_save(peer_id, peer_name).await?;
    }
    Ok(())
}

async fn handle_approval_and_save(peer_id: [u8; 32], peer_name: String) -> anyhow::Result<()> {
    use std::io::IsTerminal;
    let mut approved = true;

    if std::io::stdin().is_terminal() {
        println!("\nIncoming device pairing request:");
        println!("----------------------------------------");
        println!("  Device Name: {}", peer_name);
        println!("  Device ID:   {}", hex::encode(peer_id));
        println!("----------------------------------------");

        approved = dialoguer::Confirm::new()
            .with_prompt("Do you want to authorize and pair with this device?")
            .default(false)
            .interact()?;
    } else {
        println!(
            "Non-interactive mode: Auto-approving pairing with '{}' (ID: {})",
            peer_name,
            hex::encode(peer_id)
        );
    }

    if approved {
        let (_, mut config) = get_identity_with_merged_config()?;
        if !config.peers.iter().any(|p| p.device_id == peer_id) {
            config.peers.push(arc_core::PeerInfo {
                name: peer_name.clone(),
                device_id: peer_id,
            });
            arc_core::save_config(&config)?;
        }
        println!(
            "\nPairing completed successfully. Device '{}' is now authorized.",
            peer_name
        );
        Ok(())
    } else {
        Err(anyhow::anyhow!("Pairing rejected by user"))
    }
}
