use std::time::{Instant, Duration};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use serde::{Serialize, Deserialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};

use crate::crypto::identity::DeviceId;
use crate::protocol::messages::ArcMessage;

pub(crate) async fn send_msg_stream<S>(stream: &mut S, msg: &ArcMessage) -> Result<(), anyhow::Error>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let bytes = msg.encode()?;
    let len = bytes.len() as u32;
    
    let write_fut = async {
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&bytes).await?;
        stream.flush().await?;
        Ok::<(), anyhow::Error>(())
    };

    tokio::time::timeout(Duration::from_secs(15), write_fut).await
        .map_err(|_| anyhow::anyhow!("Write timeout exceeded"))??;
    Ok(())
}

pub(crate) async fn recv_msg_stream<S>(stream: &mut S) -> Result<ArcMessage, anyhow::Error>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let read_fut = async {
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len > 16 * 1024 * 1024 {
            return Err(anyhow::anyhow!("Message size limit exceeded ({} > 16MB)", len));
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        let (msg, _) = ArcMessage::decode(&buf)?;
        Ok::<ArcMessage, anyhow::Error>(msg)
    };

    let msg = tokio::time::timeout(Duration::from_secs(15), read_fut).await
        .map_err(|_| anyhow::anyhow!("Read timeout exceeded"))??;
    Ok(msg)
}

pub(crate) struct RateLimiter {
    bytes_per_sec: Option<u64>,
    last_tick: Instant,
}

impl RateLimiter {
    pub(crate) fn new(max_mbps: Option<u32>) -> Self {
        let bytes_per_sec = max_mbps.map(|limit| (limit as u64) * 1024 * 1024 / 8);
        Self {
            bytes_per_sec,
            last_tick: Instant::now(),
        }
    }

    pub(crate) async fn throttle(&mut self, chunk_size: usize) {
        if let Some(limit) = self.bytes_per_sec {
            if limit == 0 { return; }
            let target_duration = Duration::from_secs_f64(chunk_size as f64 / limit as f64);
            let elapsed = self.last_tick.elapsed();
            if elapsed < target_duration {
                tokio::time::sleep(target_duration - elapsed).await;
            }
            self.last_tick = Instant::now();
        }
    }
}

pub(crate) fn encrypt_signal(key_bytes: &[u8; 32], plaintext: &[u8]) -> Result<String, anyhow::Error> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let nonce_bytes: [u8; 12] = rand::random();
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| anyhow::anyhow!("signal encryption failed: {:?}", e))?;
    let mut combined = nonce_bytes.to_vec();
    combined.extend(ciphertext);
    Ok(hex::encode(combined))
}

pub(crate) fn decrypt_signal(key_bytes: &[u8; 32], hex_str: &str) -> Result<Vec<u8>, anyhow::Error> {
    let combined = hex::decode(hex_str)?;
    if combined.len() < 12 {
        return Err(anyhow::anyhow!("invalid signal length"));
    }
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let decrypted = cipher.decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| anyhow::anyhow!("decrypt failed: {:?}", e))?;
    Ok(decrypted)
}

#[derive(Serialize)]
pub(crate) struct WsJoin {
    pub(crate) r#type: &'static str,
    pub(crate) room_id: String,
    pub(crate) max_members: Option<usize>,
}

#[derive(Serialize)]
pub(crate) struct WsSignal {
    pub(crate) r#type: &'static str,
    pub(crate) room_id: String,
    pub(crate) data: String,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(dead_code)]
pub(crate) enum WsRelayMessage {
    Joined { room_id: String, member_count: u8 },
    RoomMemberCount { room_id: String, count: u8 },
    Signal { data: String },
    Error { message: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct HandshakePayload {
    pub(crate) device_id: DeviceId,
    pub(crate) device_name: String,
    pub(crate) node_addr: iroh::EndpointAddr,
    pub(crate) ephemeral_public: [u8; 32],
    pub(crate) nonce: [u8; 32],
    pub(crate) signature: Option<Vec<u8>>,
}

// ─── Public APIs ─────────────────────────────────────────────────────────────

pub async fn run_pairing_sender(
    phrase: &str,
    relay_url: &str,
    _device_name: &str,
) -> Result<[u8; 32], anyhow::Error> {
    let phrase_seed = crate::crypto::derive_key_from_phrase(phrase);
    let room_id = hex::encode(blake3::hash(&phrase_seed).as_bytes());

    let (identity, config) = crate::storage::get_or_create_identity()?;

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

    // Wait for handshake
    let mut receiver_handshake: Option<HandshakePayload> = None;
    while let Some(msg_res) = ws_read.next().await {
        let msg = msg_res?;
        if let Message::Text(text) = msg {
            if let Ok(relay_msg) = serde_json::from_str::<WsRelayMessage>(&text) {
                if let WsRelayMessage::Signal { data } = relay_msg {
                    if let Ok(decrypted) = decrypt_signal(&phrase_seed, &data) {
                        if let Ok(payload) = serde_json::from_slice::<HandshakePayload>(&decrypted) {
                            receiver_handshake = Some(payload);
                            break;
                        }
                    }
                }
            }
        }
    }

    let rx_payload = receiver_handshake.ok_or_else(|| anyhow::anyhow!("failed to receive receiver handshake"))?;

    // Verify signature
    if let Some(ref sig_bytes) = rx_payload.signature {
        let sig: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| anyhow::anyhow!("Invalid signature length"))?;
        let mut sig_input = Vec::with_capacity(64);
        sig_input.extend_from_slice(&rx_payload.nonce);
        sig_input.extend_from_slice(&rx_payload.ephemeral_public);
        if crate::crypto::identity::DeviceIdentity::verify_peer_signature(&rx_payload.device_id, &sig_input, &sig).is_err() {
            return Err(anyhow::anyhow!("Invalid handshake signature from receiver"));
        }
    } else {
        return Err(anyhow::anyhow!("Missing handshake signature from receiver"));
    }

    // Send our handshake back
    let our_nonce: [u8; 32] = rand::random();
    let mut sig_input = Vec::with_capacity(64);
    sig_input.extend_from_slice(&our_nonce);
    sig_input.extend_from_slice(&[0u8; 32]);
    let sig = identity.sign(&sig_input);
    let node_id = iroh::PublicKey::from_bytes(&identity.device_id())
        .map_err(|e| anyhow::anyhow!("invalid public key bytes: {:?}", e))?;
    let dummy_node_addr = iroh::EndpointAddr::new(node_id);
    let handshake_out = HandshakePayload {
        device_id: identity.device_id(),
        device_name: config.device_name.clone(),
        node_addr: dummy_node_addr,
        ephemeral_public: [0u8; 32],
        nonce: our_nonce,
        signature: Some(sig.to_vec()),
    };
    let handshake_bytes = serde_json::to_vec(&handshake_out)?;
    let signal_data = encrypt_signal(&phrase_seed, &handshake_bytes)?;
    let sig_req = WsSignal {
        r#type: "signal",
        room_id: room_id.clone(),
        data: signal_data,
    };
    let sig_json = serde_json::to_string(&sig_req)?;
    ws_write.send(Message::Text(sig_json.into())).await?;

    // Save peer info
    let mut updated_config = config.clone();
    if !updated_config.peers.iter().any(|p| p.device_id == rx_payload.device_id) {
        updated_config.peers.push(crate::storage::PeerInfo {
            name: rx_payload.device_name.clone(),
            device_id: rx_payload.device_id,
        });
        crate::storage::save_config(&updated_config)?;
    }

    Ok(rx_payload.device_id)
}

pub async fn run_pairing_receiver(
    phrase: &str,
    relay_url: &str,
    _device_name: &str,
) -> Result<([u8; 32], String), anyhow::Error> {
    let phrase_seed = crate::crypto::derive_key_from_phrase(phrase);
    let room_id = hex::encode(blake3::hash(&phrase_seed).as_bytes());

    let (identity, config) = crate::storage::get_or_create_identity()?;

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

    // Send handshake
    let our_nonce: [u8; 32] = rand::random();
    let mut sig_input = Vec::with_capacity(64);
    sig_input.extend_from_slice(&our_nonce);
    sig_input.extend_from_slice(&[0u8; 32]);
    let sig = identity.sign(&sig_input);
    let node_id = iroh::PublicKey::from_bytes(&identity.device_id())
        .map_err(|e| anyhow::anyhow!("invalid public key bytes: {:?}", e))?;
    let dummy_node_addr = iroh::EndpointAddr::new(node_id);
    let handshake_out = HandshakePayload {
        device_id: identity.device_id(),
        device_name: config.device_name.clone(),
        node_addr: dummy_node_addr,
        ephemeral_public: [0u8; 32],
        nonce: our_nonce,
        signature: Some(sig.to_vec()),
    };
    let handshake_bytes = serde_json::to_vec(&handshake_out)?;
    let signal_data = encrypt_signal(&phrase_seed, &handshake_bytes)?;
    let sig_req = WsSignal {
        r#type: "signal",
        room_id: room_id.clone(),
        data: signal_data,
    };
    let sig_json = serde_json::to_string(&sig_req)?;
    ws_write.send(Message::Text(sig_json.into())).await?;

    // Wait for sender handshake
    let mut sender_handshake: Option<HandshakePayload> = None;
    while let Some(msg_res) = ws_read.next().await {
        let msg = msg_res?;
        if let Message::Text(text) = msg {
            if let Ok(relay_msg) = serde_json::from_str::<WsRelayMessage>(&text) {
                if let WsRelayMessage::Signal { data } = relay_msg {
                    if let Ok(decrypted) = decrypt_signal(&phrase_seed, &data) {
                        if let Ok(payload) = serde_json::from_slice::<HandshakePayload>(&decrypted) {
                            sender_handshake = Some(payload);
                            break;
                        }
                    }
                }
            }
        }
    }

    let tx_payload = sender_handshake.ok_or_else(|| anyhow::anyhow!("failed to receive sender handshake"))?;

    // Verify signature
    if let Some(ref sig_bytes) = tx_payload.signature {
        let sig: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| anyhow::anyhow!("Invalid signature length"))?;
        let mut sig_input = Vec::with_capacity(64);
        sig_input.extend_from_slice(&tx_payload.nonce);
        sig_input.extend_from_slice(&tx_payload.ephemeral_public);
        if crate::crypto::identity::DeviceIdentity::verify_peer_signature(&tx_payload.device_id, &sig_input, &sig).is_err() {
            return Err(anyhow::anyhow!("Invalid handshake signature from sender"));
        }
    } else {
        return Err(anyhow::anyhow!("Missing handshake signature from sender"));
    }

    // Save peer info
    let mut updated_config = config.clone();
    if !updated_config.peers.iter().any(|p| p.device_id == tx_payload.device_id) {
        updated_config.peers.push(crate::storage::PeerInfo {
            name: tx_payload.device_name.clone(),
            device_id: tx_payload.device_id,
        });
        crate::storage::save_config(&updated_config)?;
    }

    Ok((tx_payload.device_id, tx_payload.device_name))
}

pub async fn check_relay_status(relay_url: &str) -> Result<Duration, anyhow::Error> {
    let start = Instant::now();
    let (ws_stream, _) = connect_async(relay_url).await?;
    let (mut ws_write, mut ws_read) = ws_stream.split();
    
    ws_write.send(Message::Ping(vec![].into())).await?;
    
    while let Some(msg_res) = ws_read.next().await {
        let msg = msg_res?;
        if let Message::Pong(_) = msg {
            return Ok(start.elapsed());
        }
    }
    Err(anyhow::anyhow!("No Pong received"))
}

pub async fn ping_peer(peer_name: &str) -> Result<Duration, anyhow::Error> {
    let (_, config) = crate::config::get_identity_with_merged_config()?;
    let peer = config.peers.iter().find(|p| p.name == peer_name)
        .ok_or_else(|| anyhow::anyhow!("Device not paired: {}", peer_name))?;

    let start = Instant::now();
    if let Ok(dm) = crate::transfer::discovery::DiscoveryManager::new() {
        if let Some(_addr) = dm.discover_device(&peer.device_id, Duration::from_millis(config.transport.mdns_browse_timeout_ms)) {
            return Ok(start.elapsed());
        }
    }

    // Fallback to check if relay is online
    check_relay_status(&config.relay_url).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    async fn test_rate_limiter_throttling() {
        let mut limiter = RateLimiter::new(Some(8)); // 8 Mbps = 1 MB/s
        let start = Instant::now();
        // First chunk call sets up the last_tick
        limiter.throttle(1_048_576).await;
        // Second chunk call will throttle based on the first chunk's size
        limiter.throttle(1_048_576).await;
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(900), "Should throttle and take ~1s, took {:?}", elapsed);
    }

    #[tokio::test]
    async fn test_rate_limiter_none() {
        let mut limiter = RateLimiter::new(None);
        let start = Instant::now();
        limiter.throttle(10_000_000).await;
        limiter.throttle(10_000_000).await;
        let elapsed = start.elapsed();
        assert!(elapsed < Duration::from_millis(50), "Should not throttle, took {:?}", elapsed);
    }
}
