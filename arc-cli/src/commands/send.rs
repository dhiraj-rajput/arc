use crate::ui::generate_phrase;
use crate::ui::spawn_progress_task;
use arc_core::get_identity_with_merged_config;
use arc_core::transfer::orchestrator::run_sender;
use arc_core::transfer::orchestrator::run_stdin_sender;
use std::path::Path;
use tokio::sync::mpsc;

#[allow(clippy::too_many_arguments)]
pub async fn exec_send(
    path: Option<String>,
    to: Option<String>,
    share: bool,
    stdin: bool,
    name: Option<String>,
    clipboard: bool,
    code: Option<String>,
    relay_override: Option<String>,
) -> anyhow::Result<()> {
    let (_, config) = get_identity_with_merged_config()?;
    let relay_url = relay_override.as_deref().unwrap_or(&config.relay_url);

    if stdin {
        let stdin_name =
            name.ok_or_else(|| anyhow::anyhow!("--name is required when sending from stdin"))?;
        let phrase = if let Some(c) = code.clone() {
            c
        } else if let Some(peer_name) = to.as_deref() {
            let peer = config
                .peers
                .iter()
                .find(|p| p.name == peer_name)
                .ok_or_else(|| anyhow::anyhow!("Device not paired: {}", peer_name))?;
            let generated = generate_phrase();
            println!(
                "Paired transfer to {}. Secret code: {}",
                peer.name, generated
            );
            generated
        } else {
            let generated = generate_phrase();
            println!("One-Shot transfer phrase: {}", generated);
            generated
        };

        let (tx, rx) = mpsc::channel(16);
        spawn_progress_task(rx, true);

        run_stdin_sender(&stdin_name, &phrase, relay_url, Some(tx)).await?;
    } else {
        let mut _temp_holder = None;
        let file_path = if clipboard {
            let text = if let Ok(mut ctx) = arboard::Clipboard::new() {
                ctx.get_text().map_err(|e| {
                    anyhow::anyhow!("Clipboard is empty or does not contain text: {:?}", e)
                })?
            } else {
                return Err(anyhow::anyhow!(
                    "Failed to initialize clipboard context. Clipboard sync might not be supported in this environment (e.g. headless WSL)."
                ));
            };
            let mut temp_file = tempfile::NamedTempFile::new()?;
            use std::io::Write;
            temp_file.write_all(text.as_bytes())?;
            temp_file.flush()?;
            let path_str = temp_file.path().to_string_lossy().to_string();
            _temp_holder = Some(temp_file);
            path_str
        } else {
            let path_str = path.ok_or_else(|| {
                anyhow::anyhow!("Path is required when not sending from stdin or clipboard")
            })?;
            let p = Path::new(&path_str);
            if !p.exists() {
                return Err(anyhow::anyhow!(
                    "Error: file or directory not found at '{}'",
                    path_str
                ));
            }

            // Check for large send confirmation (> 500 MB)
            if let Ok(meta) = std::fs::metadata(p) {
                let file_size = meta.len();
                if file_size > 500 * 1024 * 1024 {
                    println!(
                        "Warning: The file/directory is large ({:.1} MB).",
                        file_size as f64 / 1024.0 / 1024.0
                    );
                    if !dialoguer::Confirm::new()
                        .with_prompt("Are you sure you want to send this large transfer?")
                        .default(true)
                        .interact()?
                    {
                        println!("Cancelled.");
                        return Ok(());
                    }
                }
            }
            path_str
        };

        let phrase = if let Some(c) = code {
            c
        } else if let Some(peer_name) = to {
            let peer = config
                .peers
                .iter()
                .find(|p| p.name == peer_name)
                .ok_or_else(|| anyhow::anyhow!("Device not paired: {}", peer_name))?;
            let generated = generate_phrase();
            println!(
                "Paired transfer to {}. Secret code: {}",
                peer.name, generated
            );
            generated
        } else {
            let generated = generate_phrase();
            println!("One-Shot transfer phrase: {}", generated);
            generated
        };

        let (tx, rx) = mpsc::channel(16);
        spawn_progress_task(rx, true);

        run_sender(&file_path, &phrase, relay_url, share, clipboard, Some(tx)).await?;
    }
    Ok(())
}
