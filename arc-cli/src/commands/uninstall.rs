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
        let target_dir = current_exe
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let mut target_dir_clean = target_dir.clone();
        if target_dir_clean.starts_with(r"\\?\") {
            target_dir_clean = target_dir_clean[4..].to_string();
        }

        let parent_dir = current_exe
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let mut parent_dir_clean = parent_dir.clone();
        if parent_dir_clean.starts_with(r"\\?\") {
            parent_dir_clean = parent_dir_clean[4..].to_string();
        }

        // Spawn a background PowerShell command to wait 1 second, force-delete the entire folder recursively,
        // and clean the User PATH.
        std::process::Command::new("powershell")
            .args([
                "-Command",
                &format!(
                    "Start-Sleep -Seconds 1; \
                     Remove-Item -Recurse -Force '{}'; \
                     $targetDir = '{}'; \
                     $userPath = [System.Environment]::GetEnvironmentVariable('PATH', 'User'); \
                     if ($userPath) {{ \
                         $newPathElements = ($userPath -split ';') | Where-Object {{ $_.Trim().ToLower() -ne $targetDir.ToLower() -and $_.Trim() -ne '' }}; \
                         $newUserPath = $newPathElements -join ';'; \
                         [System.Environment]::SetEnvironmentVariable('PATH', $newUserPath, 'User'); \
                     }}",
                    parent_dir_clean, target_dir_clean
                ),
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
