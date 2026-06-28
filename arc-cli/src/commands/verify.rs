use std::path::Path;

use arc_core::{blake3_hash_dir, blake3_hash_file, safe_display_name};

pub async fn exec_verify(path: String, hash: String) -> anyhow::Result<()> {
    let path_obj = Path::new(&path);
    if !path_obj.exists() {
        println!("Error: Path '{}' does not exist.", path);
        std::process::exit(1);
    }

    let actual_hash = if path_obj.is_dir() {
        println!("Verifying integrity of directory: {}", path);
        blake3_hash_dir(path_obj)?
    } else {
        println!("Verifying integrity of file: {}", path);
        blake3_hash_file(path_obj)?
    };

    let hex_hash = hex::encode(actual_hash);
    if hex_hash == hash.to_lowercase() {
        println!(
            "✅ {}: OK (BLAKE3 matches)",
            safe_display_name(&path)
        );
    } else {
        println!("❌ {}: MISMATCH", safe_display_name(&path));
        println!("   Expected: {hash}");
        println!("   Actual:   {hex_hash}");
        std::process::exit(1);
    }
    Ok(())
}
