use std::process::Command;

pub async fn exec_uninstall() -> anyhow::Result<()> {
    println!("🌌 Uninstalling arc...");

    // 1. Wipe config database and keyring secrets
    let _ = arc_core::storage::wipe_config();

    // 2. Remove configuration directory recursively
    let config_path = arc_core::storage::get_config_path();
    if let Some(dir) = config_path.parent().filter(|d| d.exists()) {
        println!("Removing configuration directory: {:?}", dir);
        if let Err(e) = std::fs::remove_dir_all(dir) {
            println!("Warning: failed to remove config directory: {}", e);
        }
    }

    // 3. Remove binary itself
    let current_exe = std::env::current_exe()?;
    println!("Removing binary: {:?}", current_exe);

    #[cfg(target_os = "windows")]
    {
        let exe_str = current_exe.to_string_lossy();
        // Spawn background command to wait 1 second and then delete the exe
        Command::new("cmd")
            .args([
                "/c",
                &format!("timeout /t 1 /nobreak && del /f /q \"{}\"", exe_str),
            ])
            .spawn()?;
        println!("✨ arc has been uninstalled! The executable will be deleted in a second.");
    }

    #[cfg(not(target_os = "windows"))]
    {
        std::fs::remove_file(&current_exe)?;
        println!("✨ arc has been uninstalled successfully!");
    }

    Ok(())
}
