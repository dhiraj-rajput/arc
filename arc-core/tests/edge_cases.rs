mod common;

use std::fs;
use tempfile::tempdir;
use tokio::sync::mpsc;

use arc_core::transfer::orchestrator::{run_receiver, run_sender};

use common::{InProcessRelay, TestEnv, relay_url, write_file};

const PHRASE: &str = "acid-acme-acre-acts-aged-aide";

#[tokio::test]
async fn test_one_byte_file_transfer() {
    let _env = TestEnv::new();
    let relay = InProcessRelay::new();
    let ws_url = relay_url(relay.start("127.0.0.1:0").await);

    let src_dir = tempdir().unwrap();
    let src = src_dir.path().join("one.bin");
    write_file(&src, &[0xAB]);

    let dest_dir = tempdir().unwrap();
    let dest = dest_dir.path().to_path_buf();

    let sender = arc_core::storage::TEST_IDENTITY.scope([40u8; 32], async {
        run_sender(src.to_str().unwrap(), PHRASE, &ws_url, false, false, None).await
    });
    let receiver = arc_core::storage::TEST_IDENTITY.scope([41u8; 32], async {
        run_receiver(dest.to_str().unwrap(), PHRASE, &ws_url, None, None).await
    });
    let (s, r) = tokio::join!(sender, receiver);
    s.unwrap();
    r.unwrap();
    assert_eq!(fs::read(dest.join("one.bin")).unwrap(), vec![0xAB]);
}

#[tokio::test]
async fn test_directory_transfer() {
    let _env = TestEnv::new();
    let relay = InProcessRelay::new();
    let ws_url = relay_url(relay.start("127.0.0.1:0").await);

    let src_dir = tempdir().unwrap();
    write_file(&src_dir.path().join("a.txt"), b"aaa");
    write_file(&src_dir.path().join("sub/b.txt"), b"bbb");

    let dest_dir = tempdir().unwrap();
    let dest = dest_dir.path().to_path_buf();

    let sender = arc_core::storage::TEST_IDENTITY.scope([42u8; 32], async {
        run_sender(
            src_dir.path().to_str().unwrap(),
            PHRASE,
            &ws_url,
            false,
            false,
            None,
        )
        .await
    });
    let receiver = arc_core::storage::TEST_IDENTITY.scope([43u8; 32], async {
        run_receiver(dest.to_str().unwrap(), PHRASE, &ws_url, None, None).await
    });
    let (s, r) = tokio::join!(sender, receiver);
    s.unwrap();
    r.unwrap();

    assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"aaa");
    assert_eq!(fs::read(dest.join("sub/b.txt")).unwrap(), b"bbb");
}

#[tokio::test]
async fn test_corrupt_config_returns_error() {
    let env = TestEnv::new();
    fs::write(env.config_path(), "{ not-json").unwrap();
    let result = arc_core::storage::load_config();
    assert!(result.is_err());
}

#[tokio::test]
async fn test_resume_bitmap_roundtrip() {
    use arc_core::transfer::resume::ResumeState;

    let hash = [0x42u8; 32];
    let mut state = ResumeState::new(16, hash);
    state.mark_received(0);
    state.mark_received(3);
    state.mark_received(15);

    let bitmap = state.to_bitmap();
    let restored = ResumeState::from_bitmap(&bitmap, 16);
    assert_eq!(restored.missing_chunks(), vec![1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
    assert!(!restored.is_complete());

    for i in 0..16 {
        state.mark_received(i);
    }
    assert!(state.is_complete());
}

#[tokio::test]
async fn test_progress_channel_reports_chunks() {
    let _env = TestEnv::new();
    let relay = InProcessRelay::new();
    let ws_url = relay_url(relay.start("127.0.0.1:0").await);

    let src_dir = tempdir().unwrap();
    let src = src_dir.path().join("progress.bin");
    write_file(&src, &vec![1u8; 256 * 1024]);

    let dest_dir = tempdir().unwrap();
    let (tx, mut rx) = mpsc::channel(16);

    let sender = arc_core::storage::TEST_IDENTITY.scope([44u8; 32], async {
        run_sender(
            src.to_str().unwrap(),
            PHRASE,
            &ws_url,
            false,
            false,
            Some(tx),
        )
        .await
    });
    let receiver = arc_core::storage::TEST_IDENTITY.scope([45u8; 32], async {
        run_receiver(
            dest_dir.path().to_str().unwrap(),
            PHRASE,
            &ws_url,
            None,
            None,
        )
        .await
    });
    let (s, r) = tokio::join!(sender, receiver);
    s.unwrap();
    r.unwrap();

    let mut last = (0, 0);
    while let Ok(p) = rx.try_recv() {
        last = p;
    }
    assert!(last.0 > 0);
}

#[test]
fn test_windows_reserved_name_blocked() {
    use arc_core::security::validate_path_component;
    assert!(validate_path_component("CON").is_err());
    assert!(validate_path_component("NUL.txt").is_err());
}
