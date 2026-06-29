mod support;

use std::fs;
use std::thread;
use std::time::Duration;

use predicates::prelude::*;

use support::{InProcessRelay, TestEnv, relay_url, write_test_file};

const PHRASE: &str = "acid-acme-acre-acts-aged-aide";

fn init_relay() -> (TestEnv, String, tokio::runtime::Runtime) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = InProcessRelay::new();
    let addr = rt.block_on(relay.start("127.0.0.1:0"));
    let ws_url = relay_url(addr);
    let env = TestEnv::new();
    env.write_minimal_config(&ws_url, "test-device");
    (env, ws_url, rt)
}

#[test]
fn test_help_and_version() {
    TestEnv::new()
        .arc_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Secure, parallel P2P"));

    TestEnv::new().arc_cmd().arg("--version").assert().success();
}

#[test]
fn test_completions_bash() {
    TestEnv::new()
        .arc_cmd()
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("arc"));
}

#[test]
fn test_config_show_and_set() {
    let (env, ws_url, _rt) = init_relay();

    env.arc_cmd()
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("test-device"));

    env.arc_cmd()
        .args(["config", "set", "device_name", "renamed"])
        .assert()
        .success();

    env.arc_cmd()
        .args(["config", "get", "device_name"])
        .assert()
        .success()
        .stdout(predicate::str::contains("renamed"));

    env.arc_cmd()
        .args(["config", "set", "relay_url", &ws_url])
        .assert()
        .success();

    env.arc_cmd()
        .args(["config", "set", "quic_connect_timeout_ms", "4000"])
        .assert()
        .success();

    env.arc_cmd()
        .args(["config", "get", "quic_connect_timeout_ms"])
        .assert()
        .success()
        .stdout(predicate::str::contains("4000"));
}

#[test]
fn test_peers_list_empty() {
    let (env, _, _rt) = init_relay();
    env.arc_cmd()
        .args(["peers", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No paired devices"));
}

#[test]
fn test_peers_show_unknown() {
    let (env, _, _rt) = init_relay();
    env.arc_cmd()
        .args(["peers", "show", "missing"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Device not found"));
}

#[test]
fn test_relay_status_online() {
    let (env, ws_url, _rt) = init_relay();
    env.arc_cmd()
        .arg("--relay")
        .arg(&ws_url)
        .args(["relay", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ONLINE"));
}

#[test]
fn test_relay_status_offline() {
    let (env, _, _rt) = init_relay();
    env.arc_cmd()
        .arg("--relay")
        .arg("ws://127.0.0.1:1")
        .args(["relay", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("OFFLINE"));
}

#[test]
fn test_discover_no_devices() {
    let (env, _, _rt) = init_relay();
    env.arc_cmd()
        .args(["discover"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No arc devices found"));
}

#[test]
fn test_receive_invalid_phrase() {
    let (env, _, _rt) = init_relay();
    env.arc_cmd()
        .args(["receive", "bad-phrase", "--dir", "."])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid passphrase"));
}

#[test]
fn test_send_missing_path() {
    let (env, _, _rt) = init_relay();
    env.arc_cmd()
        .args(["send", "/nonexistent/path"])
        .assert()
        .failure();
}

#[test]
fn test_send_unpaired_target() {
    let (env, _, _rt) = init_relay();
    let file = env.config_dir.path().join("payload.txt");
    write_test_file(&file, b"hello");
    env.arc_cmd()
        .args(["send", file.to_str().unwrap(), "--to", "unknown-peer"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not paired"));
}

#[test]
fn test_verify_file_match_and_mismatch() {
    let env = TestEnv::new();
    let file = env.config_dir.path().join("verify.bin");
    write_test_file(&file, b"arc-verify-test");

    let hash = hex::encode(blake3::hash(b"arc-verify-test").as_bytes());

    env.arc_cmd()
        .args(["verify", file.to_str().unwrap(), "--hash", &hash])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));

    env.arc_cmd()
        .args([
            "verify",
            file.to_str().unwrap(),
            "--hash",
            "00".repeat(64).as_str(),
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("MISMATCH"));
}

#[test]
fn test_verify_missing_path() {
    let env = TestEnv::new();
    env.arc_cmd()
        .args(["verify", "/missing/file", "--hash", "00"])
        .assert()
        .failure();
}

#[test]
fn test_pair_cli_with_fixed_code() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = InProcessRelay::new();
    let addr = rt.block_on(relay.start("127.0.0.1:0"));
    let ws_url = relay_url(addr);

    let env_a = TestEnv::new();
    env_a.write_minimal_config(&ws_url, "device-a");
    let env_b = TestEnv::new();
    env_b.write_minimal_config(&ws_url, "device-b");

    let joiner = thread::spawn(move || {
        env_b
            .arc_cmd()
            .args(["pair", "--joiner", PHRASE, "--name", "device-b"])
            .timeout(Duration::from_secs(120))
            .assert()
            .success();
    });

    thread::sleep(Duration::from_millis(300));

    env_a
        .arc_cmd()
        .args([
            "pair",
            "--initiator",
            "--code",
            PHRASE,
            "--name",
            "device-a",
        ])
        .timeout(Duration::from_secs(120))
        .assert()
        .success();

    joiner.join().unwrap();

    env_a
        .arc_cmd()
        .args(["peers", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("device-b"));
}

#[test]
fn test_config_set_invalid_key() {
    let (env, _, _rt) = init_relay();
    env.arc_cmd()
        .args(["config", "set", "not_a_key", "value"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Unknown configuration key"));
}

#[test]
fn test_clipboard_invalid_phrase() {
    let (env, _, _rt) = init_relay();
    env.arc_cmd()
        .args(["clipboard", "bad-phrase"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid passphrase"));
}

#[test]
fn test_completions_powershell() {
    TestEnv::new()
        .arc_cmd()
        .args(["completions", "powershell"])
        .assert()
        .success()
        .stdout(predicate::str::contains("arc"));
}

#[test]
fn test_send_receive_file_e2e() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = InProcessRelay::new();
    let addr = rt.block_on(relay.start("127.0.0.1:0"));
    let ws_url = relay_url(addr);

    let sender_env = TestEnv::new();
    sender_env.write_minimal_config(&ws_url, "sender-cli");
    let receiver_env = TestEnv::new();
    receiver_env.write_minimal_config(&ws_url, "receiver-cli");

    let src = sender_env.config_dir.path().join("outbox.dat");
    let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    write_test_file(&src, &payload);

    let dest_dir = receiver_env.config_dir.path().join("inbox");
    fs::create_dir_all(&dest_dir).unwrap();

    let phrase = PHRASE;
    let dest = dest_dir.clone();

    let mut rx_cmd = receiver_env.arc_cmd();
    let receiver_handle = thread::spawn(move || {
        rx_cmd
            .args(["receive", phrase, "--dir", dest.to_str().unwrap()])
            .timeout(Duration::from_secs(120))
            .output()
    });

    thread::sleep(Duration::from_millis(500));

    let sender_res = sender_env
        .arc_cmd()
        .args(["send", src.to_str().unwrap(), "--code", phrase])
        .env("ARC_RELAY_URL", &ws_url)
        .timeout(Duration::from_secs(120))
        .output();

    let receiver_res = receiver_handle.join().unwrap();

    let sender_output = sender_res.unwrap();
    let receiver_output = receiver_res.unwrap();

    println!("--- SENDER STDOUT ---");
    println!("{}", String::from_utf8_lossy(&sender_output.stdout));
    println!("--- SENDER STDERR ---");
    println!("{}", String::from_utf8_lossy(&sender_output.stderr));

    println!("--- RECEIVER STDOUT ---");
    println!("{}", String::from_utf8_lossy(&receiver_output.stdout));
    println!("--- RECEIVER STDERR ---");
    println!("{}", String::from_utf8_lossy(&receiver_output.stderr));

    assert!(sender_output.status.success(), "sender failed");
    assert!(receiver_output.status.success(), "receiver failed");

    let received = dest_dir.join("outbox.dat");
    assert!(received.exists());
    assert_eq!(fs::read(received).unwrap(), payload);
}

#[test]
fn test_send_stdin_receive_stdout() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = InProcessRelay::new();
    let addr = rt.block_on(relay.start("127.0.0.1:0"));
    let ws_url = relay_url(addr);

    let sender_env = TestEnv::new();
    sender_env.write_minimal_config(&ws_url, "stdin-sender");
    let receiver_env = TestEnv::new();
    receiver_env.write_minimal_config(&ws_url, "stdout-receiver");

    let phrase = PHRASE;

    let mut rx_cmd = receiver_env.arc_cmd();
    let receiver_handle = thread::spawn(move || {
        rx_cmd
            .args(["receive", phrase, "--stdout"])
            .timeout(Duration::from_secs(120))
            .output()
    });

    thread::sleep(Duration::from_millis(500));

    let sender_res = sender_env
        .arc_cmd()
        .args(["send", "--stdin", "--name", "pipe.txt", "--code", phrase])
        .env("ARC_RELAY_URL", &ws_url)
        .write_stdin(b"pipe-payload")
        .timeout(Duration::from_secs(120))
        .output();

    let receiver_res = receiver_handle.join().unwrap();

    let sender_output = sender_res.unwrap();
    let receiver_output = receiver_res.unwrap();

    println!("--- SENDER STDOUT ---");
    println!("{}", String::from_utf8_lossy(&sender_output.stdout));
    println!("--- SENDER STDERR ---");
    println!("{}", String::from_utf8_lossy(&sender_output.stderr));

    println!("--- RECEIVER STDOUT ---");
    println!("{}", String::from_utf8_lossy(&receiver_output.stdout));
    println!("--- RECEIVER STDERR ---");
    println!("{}", String::from_utf8_lossy(&receiver_output.stderr));

    assert!(sender_output.status.success(), "sender failed");
    assert!(receiver_output.status.success(), "receiver failed");

    let stdout_str = String::from_utf8_lossy(&receiver_output.stdout);
    assert!(stdout_str.contains("pipe-payload"));
}

#[test]
fn test_panic_wipes_config() {
    let (env, _, _rt) = init_relay();
    env.arc_cmd().args(["config", "show"]).assert().success();
    env.arc_cmd().args(["panic"]).assert().success();
    assert!(!env.config_path().exists());
}

#[test]
fn test_cross_flow_pair_peers_send() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = InProcessRelay::new();
    let addr = rt.block_on(relay.start("127.0.0.1:0"));
    let ws_url = relay_url(addr);

    let sender_env = TestEnv::new();
    sender_env.write_minimal_config(&ws_url, "alpha");
    let receiver_env = TestEnv::new();
    receiver_env.write_minimal_config(&ws_url, "beta");

    let mut rx_cmd_1 = receiver_env.arc_cmd();
    let receiver = thread::spawn(move || {
        rx_cmd_1
            .args(["pair", "--joiner", PHRASE, "--name", "beta"])
            .timeout(Duration::from_secs(120))
            .assert()
            .success();
    });

    thread::sleep(Duration::from_millis(500));

    sender_env
        .arc_cmd()
        .args(["pair", "--initiator", "--code", PHRASE, "--name", "alpha"])
        .env("ARC_RELAY_URL", &ws_url)
        .timeout(Duration::from_secs(120))
        .assert()
        .success();

    receiver.join().unwrap();

    sender_env
        .arc_cmd()
        .args(["peers", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("beta"));

    let src = sender_env.config_dir.path().join("note.txt");
    write_test_file(&src, b"paired-send");
    let dest = receiver_env.config_dir.path().join("downloads");
    fs::create_dir_all(&dest).unwrap();
    let dest_for_receiver = dest.clone();
    let phrase = PHRASE;
    let mut rx_cmd_2 = receiver_env.arc_cmd();
    let receiver_handle = thread::spawn(move || {
        rx_cmd_2
            .args([
                "receive",
                phrase,
                "--dir",
                dest_for_receiver.to_str().unwrap(),
            ])
            .timeout(Duration::from_secs(120))
            .output()
    });
    thread::sleep(Duration::from_millis(500));

    let sender_res = sender_env
        .arc_cmd()
        .args([
            "send",
            src.to_str().unwrap(),
            "--to",
            "beta",
            "--code",
            phrase,
        ])
        .timeout(Duration::from_secs(120))
        .output();

    let receiver_res = receiver_handle.join().unwrap();

    let sender_output = sender_res.unwrap();
    let receiver_output = receiver_res.unwrap();

    println!("--- SENDER STDOUT ---");
    println!("{}", String::from_utf8_lossy(&sender_output.stdout));
    println!("--- SENDER STDERR ---");
    println!("{}", String::from_utf8_lossy(&sender_output.stderr));

    println!("--- RECEIVER STDOUT ---");
    println!("{}", String::from_utf8_lossy(&receiver_output.stdout));
    println!("--- RECEIVER STDERR ---");
    println!("{}", String::from_utf8_lossy(&receiver_output.stderr));

    assert!(sender_output.status.success(), "sender failed");
    assert!(receiver_output.status.success(), "receiver failed");

    assert_eq!(fs::read(dest.join("note.txt")).unwrap(), b"paired-send");
}

#[test]
fn test_peers_revoke_blocks_send() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = InProcessRelay::new();
    let addr = rt.block_on(relay.start("127.0.0.1:0"));
    let ws_url = relay_url(addr);

    let env = TestEnv::new();
    env.write_minimal_config(&ws_url, "solo");
    let peer_env = TestEnv::new();
    peer_env.write_minimal_config(&ws_url, "peer-x");

    let receiver = thread::spawn(move || {
        peer_env
            .arc_cmd()
            .args(["pair", "--joiner", PHRASE, "--name", "peer-x"])
            .timeout(Duration::from_secs(120))
            .assert()
            .success();
    });

    thread::sleep(Duration::from_millis(500));

    env.arc_cmd()
        .args(["pair", "--initiator", "--code", PHRASE, "--name", "solo"])
        .env("ARC_RELAY_URL", &ws_url)
        .timeout(Duration::from_secs(120))
        .assert()
        .success();

    receiver.join().unwrap();

    env.arc_cmd()
        .args(["peers", "revoke", "peer-x"])
        .assert()
        .success();

    let file = env.config_dir.path().join("x.txt");
    write_test_file(&file, b"x");

    env.arc_cmd()
        .args(["send", file.to_str().unwrap(), "--to", "peer-x"])
        .assert()
        .failure();
}

#[test]
fn test_ping_unknown_device() {
    let (env, _, _rt) = init_relay();
    env.arc_cmd()
        .args(["ping", "missing-device"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("Failed to ping"));
}
