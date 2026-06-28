mod common;

use arc_core::security::check_room_integrity;

#[test]
fn test_mitm_room_detection_via_integrity_check() {
    // INV-9: more than two members in a room must abort.
    assert!(check_room_integrity(3).is_err());
    assert!(check_room_integrity(255).is_err());
}

#[test]
fn test_terminal_injection_filename_display() {
    use arc_core::security::safe_display_name;
    let malicious = "\x1b[2J\x07delete-me";
    let safe = safe_display_name(malicious);
    assert!(!safe.chars().any(|c| c.is_control()));
}

#[test]
fn test_decompression_bomb_rejected() {
    use arc_core::compression::{decompress_with_limit, CompressionAlgo};
    let compressed = zstd::encode_all(vec![0u8; 4096].as_slice(), 3).unwrap();
    let result = decompress_with_limit(&compressed, CompressionAlgo::Zstd, 512);
    assert!(result.is_err());
}
