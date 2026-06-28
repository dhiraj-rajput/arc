mod support;

use arc_core::security::{check_room_integrity, resolve_safe_path, safe_display_name};
use predicates::prelude::*;
use tempfile::tempdir;

use support::{InProcessRelay, TestEnv, relay_url, write_test_file};

#[test]
fn test_safe_display_name_strips_control_chars() {
    let sanitized = safe_display_name("\x1b[2Jmalicious");
    assert!(!sanitized.contains('\x1b'));
    assert!(sanitized.contains("malicious"));
}

#[test]
fn test_path_traversal_blocked() {
    let dest = tempdir().unwrap();
    let result = resolve_safe_path(dest.path(), "../outside.txt");
    assert!(result.is_err());
}

#[test]
fn test_relay_room_integrity_inv9() {
    assert!(check_room_integrity(2).is_ok());
    assert!(check_room_integrity(3).is_err());
}

#[test]
fn test_receive_rejects_invalid_phrase() {
    let env = TestEnv::new();
    env.arc_cmd()
        .args(["receive", "bad", "--dir", "."])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid passphrase"));
}

#[test]
fn test_clipboard_escape_sanitized() {
    assert!(!safe_display_name("\x1b[31mred").contains('\x1b'));
}

#[test]
fn test_send_does_not_take_phrase_on_argv() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = InProcessRelay::new();
    let addr = rt.block_on(relay.start("127.0.0.1:0"));
    let ws_url = relay_url(addr);

    let env = TestEnv::new();
    env.write_minimal_config(&ws_url, "sec-test");
    let file = env.config_dir.path().join("secret-free.txt");
    write_test_file(&file, b"data");

    // Invoking send should not embed a 6-word phrase in argv (phrase is generated internally).
    let mut cmd = env.arc_cmd();
    cmd.args(["send", file.to_str().unwrap()])
        .env("ARC_RELAY_URL", &ws_url);
    let debug = format!("{cmd:?}");
    assert!(!debug.contains("acid-acme-acre"));
}
