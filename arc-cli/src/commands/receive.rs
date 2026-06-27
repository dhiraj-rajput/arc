use std::path::Path;
use tokio::sync::mpsc;
use arc_core::get_identity_with_merged_config;
use arc_core::transfer::orchestrator::run_receiver;
use crate::setup_progress_bar;
use tokio::io::AsyncWriteExt;

pub async fn exec_receive(
    phrase: String,
    dir: String,
    stdout: bool,
    relay_override: Option<String>,
) -> anyhow::Result<()> {
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

    let (tx, mut rx) = mpsc::channel(16);
    tokio::spawn(async move {
        let mut pb = None;
        while let Some((curr, total)) = rx.recv().await {
            if pb.is_none() {
                let progress = setup_progress_bar(total as u64, false);
                pb = Some(progress);
            }
            if let Some(ref progress_bar) = pb {
                progress_bar.set_position(curr as u64);
                if total > 0 && curr == total {
                    progress_bar.finish_with_message("Done");
                }
            }
        }
    });

    let stdout_tx_opt = if stdout { Some(stdout_tx) } else { None };
    let clipboard_content = run_receiver(&dir, &phrase, relay_url, Some(tx), stdout_tx_opt).await?;
    
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
