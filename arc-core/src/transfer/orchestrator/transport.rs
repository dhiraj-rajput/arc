use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::protocol::Message;

use crate::crypto::identity::DeviceId;
use crate::protocol::messages::ArcMessage;

pub(crate) async fn send_msg_stream<S>(
    stream: &mut S,
    msg: &ArcMessage,
) -> Result<(), anyhow::Error>
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

    tokio::time::timeout(Duration::from_secs(60), write_fut)
        .await
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
            return Err(anyhow::anyhow!(
                "Message size limit exceeded ({} > 16MB)",
                len
            ));
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        let (msg, _) = ArcMessage::decode(&buf)?;
        Ok::<ArcMessage, anyhow::Error>(msg)
    };

    let msg = tokio::time::timeout(Duration::from_secs(60), read_fut)
        .await
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
            if limit == 0 {
                return;
            }
            let target_duration = Duration::from_secs_f64(chunk_size as f64 / limit as f64);
            let elapsed = self.last_tick.elapsed();
            if elapsed < target_duration {
                tokio::time::sleep(target_duration - elapsed).await;
            }
            self.last_tick = Instant::now();
        }
    }
}

pub fn encrypt_signal(key_bytes: &[u8; 32], plaintext: &[u8]) -> Result<String, anyhow::Error> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let nonce_bytes: [u8; 12] = rand::random();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| anyhow::anyhow!("signal encryption failed: {:?}", e))?;
    let mut combined = nonce_bytes.to_vec();
    combined.extend(ciphertext);
    Ok(hex::encode(combined))
}

pub fn decrypt_signal(key_bytes: &[u8; 32], hex_str: &str) -> Result<Vec<u8>, anyhow::Error> {
    let combined = hex::decode(hex_str)?;
    if combined.len() < 12 {
        return Err(anyhow::anyhow!("invalid signal length"));
    }
    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let decrypted = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| anyhow::anyhow!("decrypt failed: {:?}", e))?;
    Ok(decrypted)
}

#[derive(Serialize)]
pub struct WsJoin {
    pub r#type: &'static str,
    pub room_id: String,
    pub max_members: Option<usize>,
}

#[derive(Serialize)]
pub struct WsSignal {
    pub r#type: &'static str,
    pub room_id: String,
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(dead_code)]
pub enum WsRelayMessage {
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

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;

#[derive(Clone)]
struct Member {
    id: u64,
    tx: tokio::sync::mpsc::UnboundedSender<Message>,
}

#[derive(Clone)]
struct LocalRoom {
    members: Vec<Member>,
}

pub(crate) async fn start_local_relay() -> Result<(u16, tokio::sync::oneshot::Sender<()>), anyhow::Error> {
    let listener = TcpListener::bind("0.0.0.0:0").await?;
    let local_port = listener.local_addr()?.port();
    let rooms: Arc<Mutex<HashMap<String, LocalRoom>>> = Arc::new(Mutex::new(HashMap::new()));
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                conn_res = listener.accept() => {
                    if let Ok((stream, _)) = conn_res {
                        let rooms_clone = rooms.clone();
                        tokio::spawn(async move {
                            if let Ok(ws_stream) = accept_async(stream).await {
                                let (mut ws_write, mut ws_read) = ws_stream.split();
                                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

                                let write_task = tokio::spawn(async move {
                                    while let Some(msg) = rx.recv().await {
                                        if ws_write.send(msg).await.is_err() {
                                            break;
                                        }
                                    }
                                });

                                let mut current_room: Option<(String, u64)> = None;
                                while let Some(msg_res) = ws_read.next().await {
                                    if let Ok(msg) = msg_res {
                                        if let Message::Text(text) = msg {
                                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                                                if let Some(msg_type) = val.get("type").and_then(|v| v.as_str()) {
                                                    match msg_type {
                                                        "join" => {
                                                            if let Some(room_id) = val.get("room_id").and_then(|v| v.as_str()) {
                                                                let room_id = room_id.to_string();
                                                                let mut rooms_guard = rooms_clone.lock().unwrap();
                                                                let entry = rooms_guard.entry(room_id.clone()).or_insert_with(|| LocalRoom { members: Vec::new() });
                                                                if entry.members.len() >= 2 {
                                                                    let err = serde_json::to_string(&WsRelayMessage::Error { message: "room full".to_string() }).unwrap();
                                                                    let _ = tx.send(Message::Text(err.into()));
                                                                 } else {
                                                                    let member_id = rand::random::<u64>();
                                                                    entry.members.push(Member { id: member_id, tx: tx.clone() });
                                                                    let member_count = entry.members.len() as u8;
                                                                    current_room = Some((room_id.clone(), member_id));

                                                                    let joined = serde_json::to_string(&WsRelayMessage::Joined { room_id: room_id.clone(), member_count }).unwrap();
                                                                    let _ = tx.send(Message::Text(joined.into()));

                                                                    let count_msg = serde_json::to_string(&WsRelayMessage::RoomMemberCount { room_id: room_id.clone(), count: member_count }).unwrap();
                                                                    for member in &entry.members {
                                                                        let _ = member.tx.send(Message::Text(count_msg.clone().into()));
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        "signal" => {
                                                            if let Some(data) = val.get("data").and_then(|v| v.as_str()) {
                                                                let rooms_guard = rooms_clone.lock().unwrap();
                                                                if let Some((room_id, my_id)) = &current_room {
                                                                    if let Some(room) = rooms_guard.get(room_id) {
                                                                        let signal = serde_json::to_string(&WsRelayMessage::Signal { data: data.to_string() }).unwrap();
                                                                        for member in &room.members {
                                                                            if member.id != *my_id {
                                                                                let _ = member.tx.send(Message::Text(signal.clone().into()));
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        _ => {}
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        break;
                                    }
                                }

                                if let Some((room_id, my_id)) = current_room {
                                    let mut rooms_guard = rooms_clone.lock().unwrap();
                                    if let Some(room) = rooms_guard.get_mut(&room_id) {
                                        room.members.retain(|m| m.id != my_id);
                                    }
                                    if let Some(room) = rooms_guard.get(&room_id) {
                                        if room.members.is_empty() {
                                            rooms_guard.remove(&room_id);
                                        }
                                    }
                                }
                                write_task.abort();
                            }
                        });
                    }
                }
                _ = &mut shutdown_rx => {
                    break;
                }
            }
        }
    });

    Ok((local_port, shutdown_tx))
}

// ─── Public APIs ─────────────────────────────────────────────────────────────

pub async fn run_pairing_sender(
    phrase: &str,
    relay_url: &str,
    device_name: &str,
) -> Result<([u8; 32], String), anyhow::Error> {
    let phrase_seed = crate::crypto::derive_key_from_phrase(phrase);
    let room_id = hex::encode(blake3::hash(&phrase_seed).as_bytes());

    let (identity, _) = crate::storage::get_or_create_identity()?;

    // Start local relay and register via mDNS
    let (local_port, shutdown_tx) = start_local_relay().await?;
    let daemon = ServiceDaemon::new()?;
    let local_ips = crate::transfer::discovery::get_local_ips();
    let ip_to_use = local_ips
        .first()
        .copied()
        .unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    let service_type = "_arc-pair._tcp.local.";
    let instance_name = room_id[..32].to_string();
    let host_name = format!("{}.local.", instance_name);
    let service_info = ServiceInfo::new(
        service_type,
        &instance_name,
        &host_name,
        ip_to_use,
        local_port,
        None,
    )?;
    daemon.register(service_info.clone())?;

    let local_relay_url = format!("ws://127.0.0.1:{}/ws", local_port);
    let local_ws = crate::connect_relay(&local_relay_url).await?;
    let local_relay = Some((local_port, shutdown_tx, daemon, service_info));

    // Connect to public relay in parallel
    let public_ws = crate::connect_relay(relay_url).await;

    let (mut local_ws_write, mut local_ws_read) = local_ws.split();
    let (mut public_ws_write, mut public_ws_read) = match public_ws {
        Ok(stream) => {
            let (w, r) = stream.split();
            (Some(w), Some(r))
        }
        Err(_) => (None, None),
    };

    // Join room
    let join_req = WsJoin {
        r#type: "join",
        room_id: room_id.clone(),
        max_members: Some(2),
    };
    let join_json = serde_json::to_string(&join_req)?;
    local_ws_write.send(Message::Text(join_json.clone().into())).await?;
    if let Some(ref mut w) = public_ws_write {
        let _ = w.send(Message::Text(join_json.into())).await;
    }

    // Wait for handshake
    let mut receiver_handshake: Option<HandshakePayload> = None;
    let mut ws_write_to_use = None;

    loop {
        tokio::select! {
            local_msg = local_ws_read.next() => {
                if let Some(msg_res) = local_msg {
                    let msg = msg_res?;
                    if let Message::Text(text) = msg {
                        if let Ok(WsRelayMessage::Signal { data }) = serde_json::from_str::<WsRelayMessage>(&text) {
                            if let Ok(decrypted) = decrypt_signal(&phrase_seed, &data) {
                                if let Ok(payload) = serde_json::from_slice::<HandshakePayload>(&decrypted) {
                                    receiver_handshake = Some(payload);
                                    ws_write_to_use = Some(local_ws_write);
                                    break;
                                }
                            }
                        }
                    }
                } else {
                    break;
                }
            }
            public_msg = async {
                if let Some(ref mut r) = public_ws_read {
                    r.next().await
                } else {
                    futures_util::future::pending().await
                }
            } => {
                if let Some(msg_res) = public_msg {
                    let msg = msg_res?;
                    if let Message::Text(text) = msg {
                        if let Ok(relay_msg) = serde_json::from_str::<WsRelayMessage>(&text) {
                            match relay_msg {
                                WsRelayMessage::Signal { data } => {
                                    if let Ok(decrypted) = decrypt_signal(&phrase_seed, &data) {
                                        if let Ok(payload) = serde_json::from_slice::<HandshakePayload>(&decrypted) {
                                            receiver_handshake = Some(payload);
                                            ws_write_to_use = public_ws_write;
                                            break;
                                        }
                                    }
                                }
                                WsRelayMessage::RoomMemberCount { count, .. } if count > 2 => {
                                    return Err(anyhow::anyhow!("Relay MITM detected (members > 2)"));
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }

    let rx_payload = receiver_handshake
        .ok_or_else(|| anyhow::anyhow!("failed to receive receiver handshake"))?;

    // Verify signature
    if let Some(ref sig_bytes) = rx_payload.signature {
        let sig: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;
        let mut sig_input = Vec::with_capacity(64);
        sig_input.extend_from_slice(&rx_payload.nonce);
        sig_input.extend_from_slice(&rx_payload.ephemeral_public);
        if crate::crypto::identity::DeviceIdentity::verify_peer_signature(
            &rx_payload.device_id,
            &sig_input,
            &sig,
        )
        .is_err()
        {
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
        device_name: device_name.to_string(),
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
    if let Some(mut w) = ws_write_to_use {
        w.send(Message::Text(sig_json.into())).await?;
    }

    if let Some((_, shutdown_tx, daemon, service_info)) = local_relay {
        let _ = shutdown_tx.send(());
        let _ = daemon.unregister(service_info.get_fullname());
    }

    Ok((rx_payload.device_id, rx_payload.device_name))
}

pub async fn run_pairing_receiver(
    phrase: &str,
    relay_url: &str,
    device_name: &str,
) -> Result<([u8; 32], String), anyhow::Error> {
    let phrase_seed = crate::crypto::derive_key_from_phrase(phrase);
    let room_id = hex::encode(blake3::hash(&phrase_seed).as_bytes());

    let (identity, _) = crate::storage::get_or_create_identity()?;

    println!("Scanning local network for pairing partner (mDNS)...");
    let mut resolved_addr = None;
    if let Ok(daemon) = ServiceDaemon::new() {
        let service_type = "_arc-pair._tcp.local.";
        if let Ok(receiver) = daemon.browse(service_type) {
            let start = std::time::Instant::now();
            let timeout = Duration::from_millis(1000);
            while start.elapsed() < timeout {
                if let Ok(ServiceEvent::ServiceResolved(info)) =
                    receiver.recv_timeout(Duration::from_millis(100))
                {
                    if info.get_fullname().contains(&room_id[..32]) {
                        let port = info.get_port();
                        if let Some(ip) = info.get_addresses().iter().next() {
                            resolved_addr = Some(SocketAddr::new(ip.to_ip_addr(), port));
                            break;
                        }
                    }
                }
            }
        }
    }

    let ws_stream = if let Some(addr) = resolved_addr {
        println!("mDNS pairing partner found! Establishing direct local connection...");
        let local_relay_url = format!("ws://{}:{}/ws", addr.ip(), addr.port());
        crate::connect_relay(&local_relay_url).await?
    } else {
        println!("mDNS pairing partner not found locally. Connecting to public relay at {}...", relay_url);
        crate::connect_relay(relay_url).await?
    };
    let (mut ws_write, mut ws_read) = ws_stream.split();

    // Join room
    let join_req = WsJoin {
        r#type: "join",
        room_id: room_id.clone(),
        max_members: Some(2),
    };
    let join_json = serde_json::to_string(&join_req)?;
    ws_write.send(Message::Text(join_json.into())).await?;

    // Wait for room to have 2 members before sending handshake (avoid race condition if sender joins late)
    let mut room_ready = false;
    while let Some(msg_res) = tokio::time::timeout(Duration::from_secs(10), ws_read.next())
        .await
        .map_err(|_| anyhow::anyhow!("Relay response timed out while waiting for room readiness"))?
    {
        let msg = msg_res?;
        if let Message::Text(text) = msg {
            if let Ok(relay_msg) = serde_json::from_str::<WsRelayMessage>(&text) {
                match relay_msg {
                    WsRelayMessage::Joined {
                        member_count: 2, ..
                    } => {
                        room_ready = true;
                        break;
                    }
                    WsRelayMessage::RoomMemberCount { count: 2, .. } => {
                        room_ready = true;
                        break;
                    }
                    WsRelayMessage::Error { message } => {
                        return Err(anyhow::anyhow!("Relay error: {}", message));
                    }
                    _ => {}
                }
            }
        }
    }

    if !room_ready {
        return Err(anyhow::anyhow!(
            "Relay room connection lost before pairing partner joined"
        ));
    }

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
        device_name: device_name.to_string(),
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

    // Wait for handshake payload from sender
    let mut sender_handshake: Option<HandshakePayload> = None;
    while let Some(msg_res) = ws_read.next().await {
        let msg = msg_res?;
        if let Message::Text(text) = msg {
            if let Ok(relay_msg) = serde_json::from_str::<WsRelayMessage>(&text) {
                match relay_msg {
                    WsRelayMessage::Signal { data } => {
                        if let Ok(decrypted) = decrypt_signal(&phrase_seed, &data) {
                            if let Ok(payload) =
                                serde_json::from_slice::<HandshakePayload>(&decrypted)
                            {
                                sender_handshake = Some(payload);
                                break;
                            }
                        }
                    }
                    WsRelayMessage::RoomMemberCount { count, .. } if count > 2 => {
                        return Err(anyhow::anyhow!("Relay MITM detected (members > 2)"));
                    }
                    _ => {}
                }
            }
        }
    }

    let tx_payload =
        sender_handshake.ok_or_else(|| anyhow::anyhow!("failed to receive sender handshake"))?;

    // Verify signature
    if let Some(ref sig_bytes) = tx_payload.signature {
        let sig: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;
        let mut sig_input = Vec::with_capacity(64);
        sig_input.extend_from_slice(&tx_payload.nonce);
        sig_input.extend_from_slice(&tx_payload.ephemeral_public);
        if crate::crypto::identity::DeviceIdentity::verify_peer_signature(
            &tx_payload.device_id,
            &sig_input,
            &sig,
        )
        .is_err()
        {
            return Err(anyhow::anyhow!("Invalid handshake signature from sender"));
        }
    } else {
        return Err(anyhow::anyhow!("Missing handshake signature from sender"));
    }

    Ok((tx_payload.device_id, tx_payload.device_name))
}

pub async fn check_relay_status(relay_url: &str) -> Result<Duration, anyhow::Error> {
    let start = Instant::now();
    let ws_stream = crate::connect_relay(relay_url).await?;
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
    let peer = config
        .peers
        .iter()
        .find(|p| p.name == peer_name)
        .ok_or_else(|| anyhow::anyhow!("Device not paired: {}", peer_name))?;

    let start = Instant::now();
    if let Ok(dm) = crate::transfer::discovery::DiscoveryManager::new() {
        if let Some(_addr) = dm.discover_device(
            &peer.device_id,
            Duration::from_millis(config.transport.mdns_browse_timeout_ms),
        ) {
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
        assert!(
            elapsed >= Duration::from_millis(900),
            "Should throttle and take ~1s, took {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_rate_limiter_none() {
        let mut limiter = RateLimiter::new(None);
        let start = Instant::now();
        limiter.throttle(10_000_000).await;
        limiter.throttle(10_000_000).await;
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(50),
            "Should not throttle, took {:?}",
            elapsed
        );
    }
}
