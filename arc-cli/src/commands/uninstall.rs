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
        let mut exe_str = current_exe.to_string_lossy().to_string();
        if exe_str.starts_with(r"\\?\") {
            exe_str = exe_str[4..].to_string();
        }

        // Spawn a background PowerShell command to wait 1 second and force-delete the exe.
        // PowerShell handles arguments cleanly without cmd's nested-quote stripping issues.
        std::process::Command::new("powershell")
            .args([
                "-Command",
                &format!("Start-Sleep -Seconds 1; Remove-Item -Force '{}'", exe_str),
            ])
            .spawn()?;
        println!("✨ arc has been uninstalled successfully!");
    }

    #[cfg(not(target_os = "windows"))]
    {
        std::fs::remove_file(&current_exe)?;
        println!("✨ arc has been uninstalled successfully!");
    }

    Ok(())
}
