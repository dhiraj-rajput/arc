#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use assert_cmd::Command as AssertCommand;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::protocol::Message;

pub struct TestEnv {
    pub config_dir: tempfile::TempDir,
    keyring_suffix: String,
}

impl TestEnv {
    pub fn new() -> Self {
        let config_dir = tempfile::tempdir().expect("temp config dir");
        let keyring_suffix = format!("cli-test-{}", uuid::Uuid::new_v4());
        Self {
            config_dir,
            keyring_suffix,
        }
    }

    pub fn config_path(&self) -> PathBuf {
        self.config_dir.path().join("config.json")
    }

    pub fn write_minimal_config(&self, relay_url: &str, device_name: &str) {
        std::fs::create_dir_all(self.config_dir.path()).unwrap();
        let config = serde_json::json!({
            "device_name": device_name,
            "relay_url": relay_url,
            "max_upload_mbps": null,
            "dns_probe_ipv4": "8.8.8.8:80",
            "dns_probe_ipv6": "[2001:4860:4860::8888]:80",
            "transport": {
                "quic_connect_timeout_ms": 3000,
                "p2p_racing_timeout_ms": 2000,
                "mdns_browse_timeout_ms": 500
            }
        });
        std::fs::write(
            self.config_path(),
            serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();
    }

    pub fn arc_cmd(&self) -> AssertCommand {
        let mut cmd = AssertCommand::cargo_bin("arc").expect("arc binary");
        cmd.env(arc_core::storage::ENV_CONFIG_DIR, self.config_dir.path())
            .env("ARC_KEYRING_SUFFIX", &self.keyring_suffix)
            .env("ARC_DISABLE_MDNS", "1");
        cmd
    }

    pub fn apply_to(&self, cmd: &mut Command) {
        cmd.env(arc_core::storage::ENV_CONFIG_DIR, self.config_dir.path())
            .env("ARC_KEYRING_SUFFIX", &self.keyring_suffix)
            .env("ARC_DISABLE_MDNS", "1");
    }
}

struct RelayClient {
    id: usize,
    tx: mpsc::Sender<Message>,
}

pub struct InProcessRelay {
    rooms: Arc<Mutex<std::collections::HashMap<String, Vec<RelayClient>>>>,
    next_client_id: Arc<Mutex<usize>>,
}

impl InProcessRelay {
    pub fn new() -> Self {
        Self {
            rooms: Arc::new(Mutex::new(std::collections::HashMap::new())),
            next_client_id: Arc::new(Mutex::new(0)),
        }
    }

    pub async fn start(self, addr: &str) -> SocketAddr {
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
                        let (tx, mut rx) = mpsc::channel::<Message>(32);
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
                                            let max_members =
                                                val["max_members"].as_u64().unwrap_or(2) as usize;
                                            let (joined_msg, member_msg, senders, rejected) = {
                                                let mut r = rooms.lock().unwrap();
                                                let connections =
                                                    r.entry(room_id.clone()).or_default();
                                                if connections.len() >= max_members {
                                                    (String::new(), String::new(), Vec::new(), true)
                                                } else {
                                                    connections.push(RelayClient {
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
                                                let error_msg = serde_json::json!({
                                                    "type": "error",
                                                    "message": "Room is full"
                                                })
                                                .to_string();
                                                let _ =
                                                    tx.send(Message::Text(error_msg.into())).await;
                                                break;
                                            }
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
                                                r.get(&room_id)
                                                    .map(|connections| {
                                                        connections
                                                            .iter()
                                                            .filter(|c| c.id != client_id)
                                                            .map(|c| c.tx.clone())
                                                            .collect::<Vec<_>>()
                                                    })
                                                    .unwrap_or_default()
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
                        {
                            let mut r = rooms.lock().unwrap();
                            for connections in r.values_mut() {
                                connections.retain(|c| c.id != client_id);
                            }
                            r.retain(|_, v| !v.is_empty());
                        }
                        ws_writer_task.abort();
                    }
                });
            }
        });
        local_addr
    }
}

pub fn relay_url(addr: SocketAddr) -> String {
    format!("ws://{addr}")
}

pub fn write_test_file(path: &Path, data: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, data).unwrap();
}

pub fn wait_for<F: FnMut() -> bool>(mut predicate: F, timeout: Duration) {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for condition");
}
