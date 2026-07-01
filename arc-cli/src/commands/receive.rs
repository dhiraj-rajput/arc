use crate::ui::spawn_progress_task;
use crate::ui::validate_passphrase;
use arc_core::get_identity_with_merged_config;
use arc_core::transfer::orchestrator::run_receiver;
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

pub async fn exec_receive(
    phrase: String,
    dir: String,
    stdout: bool,
    relay_override: Option<String>,
) -> anyhow::Result<()> {
    if !validate_passphrase(&phrase) {
        return Err(anyhow::anyhow!(
            "Invalid passphrase format. Must be 6 hyphen-separated alphabetic words."
        ));
    }

    let (_, config) = get_identity_with_merged_config()?;
    let relay_url = relay_override.as_deref().unwrap_or(&config.relay_url);

    let dir_path = Path::new(&dir);
    if dir_path.exists() && !dir_path.is_dir() {
        return Err(anyhow::anyhow!("Save path '{}' is not a directory", dir));
    }
    if !dir_path.exists() {
        println!("Directory '{}' does not exist. Creating it...", dir);
        std::fs::create_dir_all(dir_path)?;
    }

    let (stdout_tx, mut stdout_rx) = mpsc::channel::<Vec<u8>>(128);
    let stdout_task = tokio::spawn(async move {
        let mut stdout_writer = tokio::io::stdout();
        while let Some(chunk) = stdout_rx.recv().await {
            let _ = stdout_writer.write_all(&chunk).await;
            let _ = stdout_writer.flush().await;
        }
    });

    let (tx, rx) = mpsc::channel(16);
    spawn_progress_task(rx, false);

    let stdout_tx_opt = if stdout { Some(stdout_tx) } else { None };
    let result = run_receiver(&dir, &phrase, relay_url, Some(tx), stdout_tx_opt).await;
    let clipboard_content = match result {
        Ok(content) => content,
        Err(e) => {
            eprintln!("\nReceive failed: {}", e);
            if e.to_string().contains("relay")
                || e.to_string().contains("WebSocket")
                || e.to_string().contains("connection")
            {
                eprintln!(
                    "Tip: The relay server might be offline, or your device might not be connected to the internet."
                );
                eprintln!("   Please check your network settings and try again.");
            } else if e.to_string().contains("MITM") {
                eprintln!(
                    "Security alert: relay room integrity check failed (possible MITM eavesdropping attempt). Connection closed."
                );
            }
            return Err(e);
        }
    };

    if let Some(text) = clipboard_content {
        println!("Writing received text to system clipboard...");
        if let Ok(mut ctx) = arboard::Clipboard::new() {
            if let Err(e) = ctx.set_text(text) {
                eprintln!("Failed to write to clipboard: {:?}", e);
            } else {
                println!("Clipboard synchronized successfully!");
            }
        } else {
            eprintln!("Failed to initialize arboard clipboard context");
        }
    }

    if stdout {
        let _ = stdout_task.await;
    }
    Ok(())
}
