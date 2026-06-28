use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::protocol::Message;
use futures_util::{StreamExt, SinkExt};
use tempfile::tempdir;

use arc_core::transfer::orchestrator::{
    run_pairing_sender, run_pairing_receiver, run_sender, run_receiver,
};

struct Client {
    id: usize,
    tx: mpsc::Sender<String>,
}

struct InProcessRelay {
    rooms: Arc<Mutex<std::collections::HashMap<String, Vec<Client>>>>,
    next_client_id: Arc<Mutex<usize>>,
}

impl InProcessRelay {
    fn new() -> Self {
        Self {
            rooms: Arc::new(Mutex::new(std::collections::HashMap::new())),
            next_client_id: Arc::new(Mutex::new(0)),
        }
    }

    async fn start(self, addr: &str) -> std::net::SocketAddr {
        let listener = TcpListener::bind(addr).await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let rooms = self.rooms.clone();
        let next_client_id = self.next_client_id.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let rooms = rooms.clone();
                let next_client_id = next_client_id.clone();
                tokio::spawn(async move {
                    if let Ok(ws_stream) = accept_async(stream).await {
                        let (mut ws_write, mut ws_read) = ws_stream.split();
                        let (tx, mut rx) = mpsc::channel::<String>(32);
                        let mut current_room: Option<String> = None;

                        let client_id = {
                            let mut id_guard = next_client_id.lock().unwrap();
                            let id = *id_guard;
                            *id_guard += 1;
                            id
                        };
                        
                        let ws_writer_task = tokio::spawn(async move {
                            while let Some(msg) = rx.recv().await {
                                if ws_write.send(Message::Text(msg.into())).await.is_err() {
                                    break;
                                }
                            }
                        });

                        while let Some(Ok(Message::Text(text))) = ws_read.next().await {
                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                                let msg_type = val["type"].as_str().unwrap_or_default();
                                if msg_type == "join" {
                                    let room_id = val["room_id"].as_str().unwrap_or_default().to_string();
                                    current_room = Some(room_id.clone());
                                    
                                    let (joined_msg, member_msg, senders) = {
                                        let mut r = rooms.lock().unwrap();
                                        let connections = r.entry(room_id.clone()).or_insert_with(Vec::new);
                                        connections.push(Client { id: client_id, tx: tx.clone() });
                                        let count = connections.len();
                                        
                                        let joined = serde_json::json!({
                                            "type": "joined",
                                            "room_id": room_id,
                                            "member_count": count
                                        }).to_string();
                                        
                                        let member = serde_json::json!({
                                            "type": "room_member_count",
                                            "room_id": room_id,
                                            "count": count
                                        }).to_string();
                                        
                                        let senders: Vec<mpsc::Sender<String>> = connections.iter().map(|c| c.tx.clone()).collect();
                                        (joined, member, senders)
                                    };

                                    let _ = tx.send(joined_msg).await;
                                    for sender in senders {
                                        let _ = sender.send(member_msg.clone()).await;
                                    }
                                } else if msg_type == "signal" {
                                    let room_id = val["room_id"].as_str().unwrap_or_default().to_string();
                                    let data = val["data"].as_str().unwrap_or_default().to_string();
                                    
                                    let senders = {
                                        let r = rooms.lock().unwrap();
                                        if let Some(connections) = r.get(&room_id) {
                                            connections.iter()
                                                .filter(|c| c.id != client_id)
                                                .map(|c| c.tx.clone())
                                                .collect::<Vec<_>>()
                                        } else {
                                            Vec::new()
                                        }
                                    };
                                    
                                    let signal_msg = serde_json::json!({
                                        "type": "signal",
                                        "data": data
                                    }).to_string();
                                    
                                    for sender in senders {
                                        let _ = sender.send(signal_msg.clone()).await;
                                    }
                                }
                            }
                        }
                        
                        // Clean up on disconnect
                        if let Some(room_id) = current_room {
                            let (member_msg, senders) = {
                                let mut r = rooms.lock().unwrap();
                                if let Some(connections) = r.get_mut(&room_id) {
                                    connections.retain(|c| c.id != client_id);
                                    let count = connections.len();
                                    let member = serde_json::json!({
                                        "type": "room_member_count",
                                        "room_id": room_id,
                                        "count": count
                                    }).to_string();
                                    let senders: Vec<mpsc::Sender<String>> = connections.iter().map(|c| c.tx.clone()).collect();
                                    (Some(member), senders)
                                } else {
                                    (None, Vec::new())
                                }
                            };
                            
                            if let Some(msg) = member_msg {
                                for sender in senders {
                                    let _ = sender.send(msg.clone()).await;
                                }
                            }
                        }
                        ws_writer_task.abort();
                    }
                });
            }
        });
        local_addr
    }
}

#[tokio::test]
async fn test_integration_pairing() {
    let relay = InProcessRelay::new();
    let local_addr = relay.start("127.0.0.1:0").await;
    let ws_url = format!("ws://{}", local_addr);

    let phrase = "acid-acme-acre-acts-aged-aide";

    // Run sender and receiver pairing handshakes concurrently
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
    
    // Verify that identity keys cross-verified successfully
    let (identity_sender, _) = arc_core::storage::get_or_create_identity().unwrap();
    assert_eq!(peer_id_from_receiver, identity_sender.device_id());
}

#[tokio::test]
async fn test_integration_file_transfer() {
    let relay = InProcessRelay::new();
    let local_addr = relay.start("127.0.0.1:0").await;
    let ws_url = format!("ws://{}", local_addr);

    let phrase = "acid-acme-acre-acts-aged-aide";
    
    // Ensure pairing exists
    let (_identity, mut config) = arc_core::storage::get_or_create_identity().unwrap();
    config.relay_url = ws_url.clone();
    arc_core::storage::save_config(&config).unwrap();

    let temp_dir = tempdir().unwrap();
    let src_file_path = temp_dir.path().join("source.bin");
    
    // Create random 1MB file
    let file_data: Vec<u8> = (0..1_048_576).map(|i| (i % 256) as u8).collect();
    std::fs::write(&src_file_path, &file_data).unwrap();

    let dest_dir = tempdir().unwrap();
    let dest_dir_path = dest_dir.path().to_path_buf();

    // Trigger pairing first
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
        ).await
    });

    let receiver_fut = arc_core::storage::TEST_IDENTITY.scope([1u8; 32], async {
        run_receiver(
            dest_dir_path.to_str().unwrap(),
            phrase,
            &ws_url,
            Some(progress_tx_r),
            None,
        ).await
    });

    let (sender_res, receiver_res) = tokio::join!(sender_fut, receiver_fut);
    sender_res.expect("sender transfer failed");
    receiver_res.expect("receiver transfer failed");

    // Collect progress
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

    // Verify received file content
    let received_file_path = dest_dir_path.join("source.bin");
    assert!(received_file_path.exists());
    let received_data = std::fs::read(&received_file_path).unwrap();
    assert_eq!(received_data, file_data);
}

#[tokio::test]
async fn test_integration_empty_file() {
    let relay = InProcessRelay::new();
    let local_addr = relay.start("127.0.0.1:0").await;
    let ws_url = format!("ws://{}", local_addr);

    let phrase = "acid-acme-acre-acts-aged-aide";
    let (_, config) = arc_core::storage::get_or_create_identity().unwrap();

    let temp_dir = tempdir().unwrap();
    let src_file_path = temp_dir.path().join("empty.bin");
    std::fs::write(&src_file_path, b"").unwrap();

    let dest_dir = tempdir().unwrap();
    let dest_dir_path = dest_dir.path().to_path_buf();

    // Trigger pairing
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
        ).await
    });

    let receiver_fut = arc_core::storage::TEST_IDENTITY.scope([1u8; 32], async {
        run_receiver(
            dest_dir_path.to_str().unwrap(),
            phrase,
            &ws_url,
            None,
            None,
        ).await
    });

    let (sender_res, receiver_res) = tokio::join!(sender_fut, receiver_fut);
    sender_res.expect("sender empty transfer failed");
    receiver_res.expect("receiver empty transfer failed");

    let received_file_path = dest_dir_path.join("empty.bin");
    assert!(received_file_path.exists());
    let received_data = std::fs::read(&received_file_path).unwrap();
    assert!(received_data.is_empty());
}
