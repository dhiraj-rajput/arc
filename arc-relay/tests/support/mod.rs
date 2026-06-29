use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::protocol::Message;

struct Client {
    id: usize,
    tx: mpsc::Sender<String>,
}

pub struct InProcessRelay {
    rooms: Arc<Mutex<HashMap<String, Vec<Client>>>>,
    next_client_id: Arc<Mutex<usize>>,
}

impl InProcessRelay {
    pub fn new() -> Self {
        Self {
            rooms: Arc::new(Mutex::new(HashMap::new())),
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
                        let (tx, mut rx) = mpsc::channel::<String>(32);

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
                                    let room_id =
                                        val["room_id"].as_str().unwrap_or_default().to_string();
                                    let max_members =
                                        val["max_members"].as_u64().unwrap_or(2) as usize;
                                    let (joined_msg, member_msg, senders, rejected) = {
                                        let mut r = rooms.lock().unwrap();
                                        let connections =
                                            r.entry(room_id.clone()).or_insert_with(Vec::new);
                                        if connections.len() >= max_members {
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
                                            let senders: Vec<mpsc::Sender<String>> =
                                                connections.iter().map(|c| c.tx.clone()).collect();
                                            (joined, member, senders, false)
                                        }
                                    };
                                    if rejected {
                                        let error_msg = serde_json::json!({
                                            "type": "error",
                                            "message": "Room is full"
                                        })
                                        .to_string();
                                        let _ = tx.send(error_msg).await;
                                        break;
                                    }

                                    let _ = tx.send(joined_msg).await;
                                    for sender in senders {
                                        let _ = sender.send(member_msg.clone()).await;
                                    }
                                } else if msg_type == "signal" {
                                    let room_id =
                                        val["room_id"].as_str().unwrap_or_default().to_string();
                                    let data = val["data"].as_str().unwrap_or_default().to_string();
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
                                        let _ = sender.send(signal_msg.clone()).await;
                                    }
                                }
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
