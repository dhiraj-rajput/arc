mod common;

use tempfile::tempdir;
use tokio::sync::mpsc;

use arc_core::transfer::orchestrator::{
    run_pairing_receiver, run_pairing_sender, run_receiver, run_sender,
};

use common::{InProcessRelay, TestEnv, relay_url, write_file};

#[tokio::test]
async fn test_integration_pairing() {
    let _env = TestEnv::new();
    let relay = InProcessRelay::new();
    let local_addr = relay.start("127.0.0.1:0").await;
    let ws_url = relay_url(local_addr);

    let phrase = "acid-acme-acre-acts-aged-aide";

    let sender_fut = arc_core::storage::TEST_IDENTITY.scope([0u8; 32], async {
        run_pairing_sender(phrase, &ws_url, "sender-device").await
    });
    let receiver_fut = arc_core::storage::TEST_IDENTITY.scope([1u8; 32], async {
        run_pairing_receiver(phrase, &ws_url, "receiver-device").await
    });

    let (sender_res, receiver_res) = tokio::join!(sender_fut, receiver_fut);

    let _peer_id_from_sender = sender_res.expect("sender pairing failed");
    let (peer_id_from_receiver, receiver_name) = receiver_res.expect("receiver pairing failed");

    assert_eq!(receiver_name, "sender-device");

    let expected_device_id = arc_core::storage::TEST_IDENTITY
        .scope([0u8; 32], async {
            let (identity_sender, _) = arc_core::storage::get_or_create_identity().unwrap();
            identity_sender.device_id()
        })
        .await;
    assert_eq!(peer_id_from_receiver, expected_device_id);
}

#[tokio::test]
async fn test_integration_file_transfer() {
    let _env = TestEnv::new();
    let relay = InProcessRelay::new();
    let local_addr = relay.start("127.0.0.1:0").await;
    let ws_url = relay_url(local_addr);

    let phrase = "acid-acme-acre-acts-aged-aide";

    let (_identity, mut config) = arc_core::storage::get_or_create_identity().unwrap();
    config.relay_url = ws_url.clone();
    arc_core::storage::save_config(&config).unwrap();

    let temp_dir = tempdir().unwrap();
    let src_file_path = temp_dir.path().join("source.bin");

    let file_data: Vec<u8> = (0..1_048_576).map(|i| (i % 256) as u8).collect();
    write_file(&src_file_path, &file_data);

    let dest_dir = tempdir().unwrap();
    let dest_dir_path = dest_dir.path().to_path_buf();

    let p_sender = arc_core::storage::TEST_IDENTITY.scope([0u8; 32], async {
        run_pairing_sender(phrase, &ws_url, &config.device_name).await
    });
    let p_receiver = arc_core::storage::TEST_IDENTITY.scope([1u8; 32], async {
        run_pairing_receiver(phrase, &ws_url, "test-peer").await
    });
    let _ = tokio::join!(p_sender, p_receiver);

    let (progress_tx_s, mut progress_rx_s) = mpsc::channel(16);
    let (progress_tx_r, mut progress_rx_r) = mpsc::channel(16);

    let sender_fut = arc_core::storage::TEST_IDENTITY.scope([0u8; 32], async {
        run_sender(
            src_file_path.to_str().unwrap(),
            phrase,
            &ws_url,
            false,
            false,
            Some(progress_tx_s),
        )
        .await
    });

    let receiver_fut = arc_core::storage::TEST_IDENTITY.scope([1u8; 32], async {
        run_receiver(
            dest_dir_path.to_str().unwrap(),
            phrase,
            &ws_url,
            Some(progress_tx_r),
            None,
        )
        .await
    });

    let (sender_res, receiver_res) = tokio::join!(sender_fut, receiver_fut);
    sender_res.expect("sender transfer failed");
    receiver_res.expect("receiver transfer failed");

    let mut last_progress_s = (0, 0);
    while let Ok(progress) = progress_rx_s.try_recv() {
        last_progress_s = progress;
    }
    let mut last_progress_r = (0, 0);
    while let Ok(progress) = progress_rx_r.try_recv() {
        last_progress_r = progress;
    }

    assert!(last_progress_s.0 > 0);
    assert!(last_progress_r.0 > 0);

    let received_file_path = dest_dir_path.join("source.bin");
    assert!(received_file_path.exists());
    let received_data = std::fs::read(&received_file_path).unwrap();
    assert_eq!(received_data, file_data);
}

#[tokio::test]
async fn test_integration_empty_file() {
    let _env = TestEnv::new();
    let relay = InProcessRelay::new();
    let local_addr = relay.start("127.0.0.1:0").await;
    let ws_url = relay_url(local_addr);

    let phrase = "acid-acme-acre-acts-aged-aide";
    let (_, config) = arc_core::storage::get_or_create_identity().unwrap();

    let temp_dir = tempdir().unwrap();
    let src_file_path = temp_dir.path().join("empty.bin");
    write_file(&src_file_path, b"");

    let dest_dir = tempdir().unwrap();
    let dest_dir_path = dest_dir.path().to_path_buf();

    let p_sender = arc_core::storage::TEST_IDENTITY.scope([0u8; 32], async {
        run_pairing_sender(phrase, &ws_url, &config.device_name).await
    });
    let p_receiver = arc_core::storage::TEST_IDENTITY.scope([1u8; 32], async {
        run_pairing_receiver(phrase, &ws_url, "test-peer").await
    });
    let _ = tokio::join!(p_sender, p_receiver);

    let sender_fut = arc_core::storage::TEST_IDENTITY.scope([0u8; 32], async {
        run_sender(
            src_file_path.to_str().unwrap(),
            phrase,
            &ws_url,
            false,
            false,
            None,
        )
        .await
    });

    let receiver_fut = arc_core::storage::TEST_IDENTITY.scope([1u8; 32], async {
        run_receiver(dest_dir_path.to_str().unwrap(), phrase, &ws_url, None, None).await
    });

    let (sender_res, receiver_res) = tokio::join!(sender_fut, receiver_fut);
    sender_res.expect("sender empty transfer failed");
    receiver_res.expect("receiver empty transfer failed");

    let received_file_path = dest_dir_path.join("empty.bin");
    assert!(received_file_path.exists());
    let received_data = std::fs::read(&received_file_path).unwrap();
    assert!(received_data.is_empty());
}

#[tokio::test]
async fn test_integration_third_member_rejected() {
    let _env = TestEnv::new();
    let relay = InProcessRelay::new();
    let local_addr = relay.start("127.0.0.1:0").await;
    let ws_url = relay_url(local_addr);
    let phrase = "acid-acme-acre-acts-aged-aide";

    let first = arc_core::storage::TEST_IDENTITY.scope([0u8; 32], async {
        run_pairing_sender(phrase, &ws_url, "device-a").await
    });
    let second = arc_core::storage::TEST_IDENTITY.scope([1u8; 32], async {
        run_pairing_receiver(phrase, &ws_url, "device-b").await
    });
    let (r1, r2) = tokio::join!(first, second);
    assert!(r1.is_ok());
    assert!(r2.is_ok());

    let third = arc_core::storage::TEST_IDENTITY.scope([2u8; 32], async {
        run_pairing_receiver(phrase, &ws_url, "device-c").await
    });
    let third_res = third.await;
    assert!(third_res.is_err());
}
