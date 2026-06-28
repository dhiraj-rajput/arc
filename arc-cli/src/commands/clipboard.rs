use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use tokio::sync::mpsc;
use serde::{Serialize, Deserialize};

use arc_core::get_identity_with_merged_config;
use arc_core::transfer::orchestrator::transport::{WsJoin, WsSignal, WsRelayMessage, encrypt_signal, decrypt_signal};
use crate::clipboard::{ClipboardWatcher, ClipboardEvent, ClipboardContent, apply_remote_clipboard};

#[derive(Serialize, Deserialize, Debug)]
struct ClipboardPayload {
    sequence: u64,
    source_device_id: [u8; 32],
    text: String,
}

pub async fn exec_clipboard_sync(phrase: String, relay_override: Option<String>) -> anyhow::Result<()> {
    if !crate::ui::validate_passphrase(&phrase) {
        return Err(anyhow::anyhow!(
            "Invalid passphrase format. Must be 6 hyphen-separated alphabetic words."
        ));
    }

    let (identity, config) = get_identity_with_merged_config()?;
    let relay_url = relay_override.as_deref().unwrap_or(&config.relay_url);
    
    let phrase_seed = arc_core::crypto::derive_key_from_phrase(&phrase);
    let room_id = hex::encode(blake3::hash(&phrase_seed).as_bytes());
    
    println!("Connecting to relay for clipboard synchronization...");
    let (ws_stream, _) = connect_async(relay_url).await?;
    let (mut ws_write, mut ws_read) = ws_stream.split();
    
    // Join room
    let join_req = WsJoin {
        r#type: "join",
        room_id: room_id.clone(),
        max_members: Some(2),
    };
    let join_json = serde_json::to_string(&join_req)?;
    ws_write.send(Message::Text(join_json.into())).await?;
    
    println!("Joined room. Starting clipboard sync daemon...");
    println!("Monitoring clipboard... Press Ctrl+C to stop.");
    
    let device_id = identity.device_id();
    let watcher = ClipboardWatcher::new(device_id, 500);
    let mut local_rx = watcher.start();
    
    let (tx_out, mut rx_out) = mpsc::channel::<String>(16);
    
    // Task to forward local clipboard updates to the WebSocket stream
    let room_id_clone = room_id.clone();
    tokio::spawn(async move {
        while let Some(event) = local_rx.recv().await {
            if let ClipboardContent::Text(text) = event.content {
                let payload = ClipboardPayload {
                    sequence: event.sequence,
                    source_device_id: event.source_device_id,
                    text,
                };
                let enc_res = serde_json::to_vec(&payload)
                    .map_err(|e| anyhow::anyhow!(e))
                    .and_then(|bytes| encrypt_signal(&phrase_seed, &bytes));
                if let Ok(enc) = enc_res {
                    let sig_req = WsSignal {
                        r#type: "signal",
                        room_id: room_id_clone.clone(),
                        data: enc,
                    };
                    if let Ok(sig_json) = serde_json::to_string(&sig_req) {
                        let _ = tx_out.send(sig_json).await;
                    }
                }
            }
        }
    });

    // Loop to read incoming WebSocket signals and process local clipboard changes
    loop {
        tokio::select! {
            Some(msg_str) = rx_out.recv() => {
                if let Err(e) = ws_write.send(Message::Text(msg_str.into())).await {
                    eprintln!("Failed to send update to relay: {:?}", e);
                    break;
                }
            }
            Some(msg_res) = ws_read.next() => {
                let msg = match msg_res {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("Connection error: {:?}", e);
                        break;
                    }
                };
                if let Message::Text(text) = msg {
                    let payload_res = serde_json::from_str::<WsRelayMessage>(&text)
                        .map_err(|e| anyhow::anyhow!(e))
                        .and_then(|relay_msg| match relay_msg {
                            WsRelayMessage::Signal { data } => Ok(data),
                            _ => Err(anyhow::anyhow!("Not a signal")),
                        })
                        .and_then(|data| decrypt_signal(&phrase_seed, &data))
                        .and_then(|decrypted| serde_json::from_slice::<ClipboardPayload>(&decrypted).map_err(|e| anyhow::anyhow!(e)));

                    if let Ok(payload) = payload_res {
                        let event = ClipboardEvent {
                            sequence: payload.sequence,
                            source_device_id: payload.source_device_id,
                            content: ClipboardContent::Text(payload.text),
                        };
                        match apply_remote_clipboard(&event, &device_id) {
                            Ok(true) => println!("Applied remote clipboard update (seq: {})", event.sequence),
                            Ok(false) => {}, // Echo filter
                            Err(e) => eprintln!("Failed to apply remote clipboard: {:?}", e),
                        }
                    }
                }
            }
        }
    }
    
    watcher.stop();
    Ok(())
}
