#![allow(dead_code)]

//! Shared integration-test harness: in-process relay and isolated config dirs.

use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::protocol::Message;

struct Client {
    id: usize,
    tx: mpsc::Sender<Message>,
}

/// Minimal WebSocket relay matching arc-core signaling expectations.
pub struct InProcessRelay {
    rooms: Arc<Mutex<HashMap<String, Vec<Client>>>>,
    next_client_id: Arc<Mutex<usize>>,
    max_members: usize,
}

impl InProcessRelay {
    pub fn new() -> Self {
        Self {
            rooms: Arc::new(Mutex::new(HashMap::new())),
            next_client_id: Arc::new(Mutex::new(0)),
            max_members: 2,
        }
    }

    pub async fn start(self, addr: &str) -> SocketAddr {
        let listener = TcpListener::bind(addr).await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let rooms = self.rooms.clone();
        let next_client_id = self.next_client_id.clone();
        let max_members = self.max_members;

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let rooms = rooms.clone();
                let next_client_id = next_client_id.clone();
                tokio::spawn(async move {
                    if let Ok(ws_stream) = accept_async(stream).await {
                        let (mut ws_write, mut ws_read) = ws_stream.split();
                        let (tx, mut rx) = mpsc::channel::<Message>(32);
                        let mut current_room: Option<String> = None;

                        let client_id = {
                            let mut id_guard = next_client_id.lock().unwrap();
                            let id = *id_guard;
                            *id_guard += 1;
                            id
                        };

                        let ws_writer_task = tokio::spawn(async move {
                            while let Some(msg) = rx.recv().await {
                                if ws_write.send(msg).await.is_err() {
                                    break;
                                }
                            }
                        });

                        while let Some(Ok(msg)) = ws_read.next().await {
                            match msg {
                                Message::Text(text) => {
                                    if let Ok(val) =
                                        serde_json::from_str::<serde_json::Value>(&text)
                                    {
                                        let msg_type = val["type"].as_str().unwrap_or_default();
                                        if msg_type == "join" {
                                            let room_id = val["room_id"]
                                                .as_str()
                                                .unwrap_or_default()
                                                .to_string();
                                            let requested_max = val["max_members"]
                                                .as_u64()
                                                .unwrap_or(max_members as u64)
                                                as usize;
                                            let effective_max = requested_max.min(max_members);

                                            let (joined_msg, member_msg, senders, rejected) = {
                                                let mut r = rooms.lock().unwrap();
                                                let connections =
                                                    r.entry(room_id.clone()).or_default();
                                                if connections.len() >= effective_max {
                                                    (String::new(), String::new(), Vec::new(), true)
                                                } else {
                                                    connections.push(Client {
                                                        id: client_id,
                                                        tx: tx.clone(),
                                                    });
                                                    let count = connections.len();
                                                    let joined = serde_json::json!({
                                                        "type": "joined",
                                                        "room_id": room_id,
                                                        "member_count": count
                                                    })
                                                    .to_string();
                                                    let member = serde_json::json!({
                                                        "type": "room_member_count",
                                                        "room_id": room_id,
                                                        "count": count
                                                    })
                                                    .to_string();
                                                    let senders: Vec<mpsc::Sender<Message>> =
                                                        connections
                                                            .iter()
                                                            .map(|c| c.tx.clone())
                                                            .collect();
                                                    (joined, member, senders, false)
                                                }
                                            };

                                            if rejected {
                                                let err = serde_json::json!({
                                                    "type": "error",
                                                    "message": format!("room is full (max {} members)", effective_max)
                                                })
                                                .to_string();
                                                let _ = tx.send(Message::Text(err.into())).await;
                                                break;
                                            }

                                            current_room = Some(room_id.clone());
                                            let _ = tx.send(Message::Text(joined_msg.into())).await;
                                            for sender in senders {
                                                let _ = sender
                                                    .send(Message::Text(member_msg.clone().into()))
                                                    .await;
                                            }
                                        } else if msg_type == "signal" {
                                            let room_id = val["room_id"]
                                                .as_str()
                                                .unwrap_or_default()
                                                .to_string();
                                            let data = val["data"]
                                                .as_str()
                                                .unwrap_or_default()
                                                .to_string();

                                            let senders = {
                                                let r = rooms.lock().unwrap();
                                                if let Some(connections) = r.get(&room_id) {
                                                    connections
                                                        .iter()
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
                                            })
                                            .to_string();

                                            for sender in senders {
                                                let _ = sender
                                                    .send(Message::Text(signal_msg.clone().into()))
                                                    .await;
                                            }
                                        }
                                    }
                                }
                                Message::Ping(ping) => {
                                    let _ = tx.send(Message::Pong(ping)).await;
                                }
                                Message::Close(_) => {
                                    break;
                                }
                                _ => {}
                            }
                        }

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
                                    })
                                    .to_string();
                                    let senders: Vec<mpsc::Sender<Message>> =
                                        connections.iter().map(|c| c.tx.clone()).collect();
                                    (Some(member), senders)
                                } else {
                                    (None, Vec::new())
                                }
                            };

                            if let Some(msg) = member_msg {
                                for sender in senders {
                                    let _ = sender.send(Message::Text(msg.clone().into())).await;
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

impl Default for InProcessRelay {
    fn default() -> Self {
        Self::new()
    }
}

/// Isolated config directory for integration tests.
pub struct TestEnv {
    config_dir: tempfile::TempDir,
}

impl TestEnv {
    pub fn new() -> Self {
        let config_dir = tempfile::tempdir().expect("temp config dir");
        unsafe {
            std::env::set_var(arc_core::storage::ENV_CONFIG_DIR, config_dir.path());
            std::env::set_var(
                "ARC_KEYRING_SUFFIX",
                format!("test-{}", uuid::Uuid::new_v4()),
            );
            std::env::set_var("ARC_DISABLE_MDNS", "1");
            std::env::set_var("ARC_TEST_MODE", "1");
        }
        Self { config_dir }
    }

    pub fn config_path(&self) -> PathBuf {
        self.config_dir.path().join("config.json")
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        unsafe {
            std::env::remove_var(arc_core::storage::ENV_CONFIG_DIR);
            std::env::remove_var("ARC_KEYRING_SUFFIX");
            std::env::remove_var("ARC_DISABLE_MDNS");
            std::env::remove_var("ARC_TEST_MODE");
        }
    }
}

pub fn relay_url(addr: SocketAddr) -> String {
    format!("ws://{addr}")
}

pub fn write_file(path: &Path, data: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, data).unwrap();
}
