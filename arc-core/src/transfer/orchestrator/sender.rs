use futures_util::{SinkExt, StreamExt};
use serde_json;
use std::path::Path;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::Message;
use uuid::Uuid;

use crate::compression::CompressionAlgo;
use crate::crypto::cipher::CipherSuite;
use crate::crypto::identity::EphemeralKeyPair;
use crate::machine::MachineCapacity;
use crate::protocol::messages::{ArcMessage, TransferKind};
use crate::transfer::chunker::AdaptiveChunker;
use crate::transfer::pipeline::{RawChunk, TransferPipeline};
use tracing::info;

use super::transport::{
    HandshakePayload, RateLimiter, WsJoin, WsRelayMessage, WsSignal, decrypt_signal,
    encrypt_signal, recv_msg_stream, send_msg_stream,
};

#[allow(clippy::too_many_arguments)]
async fn run_quic_sender_session(
    conn: &iroh::endpoint::Connection,
    path: &Path,
    mut offer: ArcMessage,
    chunker: &AdaptiveChunker,
    session_keys: &crate::crypto::identity::SessionKeys,
    expected_peer_id: [u8; 32],
    accepted_bitmap: Option<Vec<u8>>,
    progress_tx: Option<mpsc::Sender<(u32, u32)>>,
) -> Result<(), anyhow::Error> {
    let (mut send_stream, mut recv_stream) = conn.open_bi().await?;
    use crate::protocol::state::{SessionState, next_state, validate_message_for_state};
    let mut current_state = SessionState::Connected;

    // 1. Hello exchange
    let (identity, _config) = crate::storage::get_or_create_identity()?;
    let hello = ArcMessage::Hello {
        protocol_version: 1,
        device_id: identity.device_id(),
        nonce: rand::random(),
        capabilities: crate::protocol::capability::default_capabilities(),
    };
    send_msg_stream(&mut send_stream, &hello).await?;

    let hello_ack = recv_msg_stream(&mut recv_stream).await?;
    validate_message_for_state(&hello_ack, &current_state)?;
    current_state = next_state(&current_state, &hello_ack).unwrap_or(current_state);

    let (peer_device_id, selected_capabilities) = match hello_ack {
        ArcMessage::HelloAck {
            protocol_version,
            device_id,
            selected_capabilities,
            ..
        } => {
            if protocol_version != 1 {
                return Err(anyhow::anyhow!(
                    "Unsupported protocol version: {}",
                    protocol_version
                ));
            }
            (device_id, selected_capabilities)
        }
        _ => return Err(anyhow::anyhow!("Expected HelloAck")),
    };

    if selected_capabilities.is_empty() {
        return Err(anyhow::anyhow!(
            "Capability negotiation failed: peer returned empty capabilities"
        ));
    }

    use crate::protocol::capability::CapabilityType;
    let has_zstd = selected_capabilities
        .iter()
        .any(|c| c.cap_type == CapabilityType::CompressionZstd);
    let has_lz4 = selected_capabilities
        .iter()
        .any(|c| c.cap_type == CapabilityType::CompressionLz4);

    if let ArcMessage::TransferOffer {
        ref mut compression,
        ..
    } = offer
    {
        let negotiated = match *compression {
            crate::compression::CompressionAlgo::Zstd => {
                if has_zstd {
                    crate::compression::CompressionAlgo::Zstd
                } else if has_lz4 {
                    crate::compression::CompressionAlgo::Lz4
                } else {
                    crate::compression::CompressionAlgo::None
                }
            }
            crate::compression::CompressionAlgo::Lz4 => {
                if has_lz4 {
                    crate::compression::CompressionAlgo::Lz4
                } else if has_zstd {
                    crate::compression::CompressionAlgo::Zstd
                } else {
                    crate::compression::CompressionAlgo::None
                }
            }
            crate::compression::CompressionAlgo::None => crate::compression::CompressionAlgo::None,
        };
        tracing::info!(
            "Negotiated compression: {:?} (proposed: {:?})",
            negotiated,
            *compression
        );
        *compression = negotiated;
    }

    if peer_device_id != expected_peer_id {
        return Err(anyhow::anyhow!(
            "Unexpected peer device ID: expected {}",
            hex::encode(expected_peer_id)
        ));
    }

    // 2. Receive AuthChallenge
    let challenge_msg = recv_msg_stream(&mut recv_stream).await?;
    validate_message_for_state(&challenge_msg, &current_state)?;

    let challenge = match challenge_msg {
        ArcMessage::AuthChallenge { challenge } => challenge,
        _ => return Err(anyhow::anyhow!("Expected AuthChallenge")),
    };

    // 3. Send AuthResponse containing signature
    let signature = identity.sign(&challenge);
    let response = ArcMessage::AuthResponse { signature };
    send_msg_stream(&mut send_stream, &response).await?;

    // 4. Wait for AuthOk
    let ok_msg = recv_msg_stream(&mut recv_stream).await?;
    validate_message_for_state(&ok_msg, &current_state)?;
    if let Some(next) = next_state(&current_state, &ok_msg) {
        current_state = next;
    }

    match ok_msg {
        ArcMessage::AuthOk => {}
        ArcMessage::AuthFail { reason } => {
            return Err(anyhow::anyhow!("Authentication failed: {:?}", reason));
        }
        _ => return Err(anyhow::anyhow!("Expected AuthOk or AuthFail")),
    }

    // Send TransferOffer
    send_msg_stream(&mut send_stream, &offer).await?;

    // Wait for TransferAccept
    let accept_msg = recv_msg_stream(&mut recv_stream).await?;
    validate_message_for_state(&accept_msg, &current_state)?;
    if let Some(next) = next_state(&current_state, &accept_msg) {
        current_state = next;
    }

    let resume_bitmap = match accept_msg {
        ArcMessage::TransferAccept { resume_bitmap, .. } => resume_bitmap,
        ArcMessage::TransferReject { reason, .. } => {
            return Err(anyhow::anyhow!("Transfer rejected by receiver: {}", reason));
        }
        _ => return Err(anyhow::anyhow!("Expected TransferAccept or TransferReject")),
    };

    info!("Transfer accepted over QUIC; starting chunk stream");

    // Create the pipeline
    let session_id = session_keys.session_id;
    let suite = CipherSuite::ChaCha20Poly1305Blake3;
    let compression = match &offer {
        ArcMessage::TransferOffer { compression, .. } => *compression,
        _ => crate::compression::CompressionAlgo::None,
    };
    let mut pipeline = TransferPipeline::new(
        chunker.config.pipeline_buffers,
        chunker.config.parallel_streams,
        compression,
        session_id,
        session_keys.sender_key,
        suite,
    );

    // Read chunks in a separate task dynamically to prevent loading the entire file into RAM (OOM safety)
    let path_clone = path.to_path_buf();
    let chunk_size = chunker.config.chunk_size as usize;
    let chunk_count = chunker.chunk_count;
    let pipeline_tx = pipeline.clone_tx().expect("pipeline should be open");
    let accepted_bitmap_reader = resume_bitmap.clone().or(accepted_bitmap.clone());
    tokio::spawn(async move {
        let mut file = match tokio::fs::File::open(&path_clone).await {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(?path_clone, "Failed to open file for streaming: {:?}", e);
                return;
            }
        };
        use std::io::SeekFrom;
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncSeekExt;
        let mut buf = vec![0u8; chunk_size];
        let mut index = 0u32;
        loop {
            if index >= chunk_count {
                break;
            }

            // Check if this chunk is already received by the receiver
            let skip_chunk = if let Some(ref bitmap) = accepted_bitmap_reader {
                let byte = index as usize / 8;
                let bit = index % 8;
                byte < bitmap.len() && (bitmap[byte] >> bit) & 1 == 1
            } else {
                false
            };

            if skip_chunk {
                // Seek past this chunk
                if let Err(e) = file.seek(SeekFrom::Current(chunk_size as i64)).await {
                    tracing::error!(index, "Failed to seek file: {:?}", e);
                    break;
                }
                index += 1;
                continue;
            }

            let mut bytes_read = 0;
            while bytes_read < chunk_size {
                match file.read(&mut buf[bytes_read..]).await {
                    Ok(0) => break, // EOF
                    Ok(n) => bytes_read += n,
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => {
                        tracing::error!(index, "Failed to read file chunk: {:?}", e);
                        return;
                    }
                }
            }

            if bytes_read == 0 {
                break;
            }

            let data = buf[..bytes_read].to_vec();
            let is_last = index + 1 == chunk_count;
            if pipeline_tx
                .send(RawChunk {
                    index,
                    data,
                    is_last,
                })
                .await
                .is_err()
            {
                break;
            }
            index += 1;
        }
    });
    pipeline.close();

    // Receive processed chunks from pipeline
    let mut pipeline_rx = {
        let (tx, rx) = mpsc::channel(16);
        let tx_clone = tx.clone();
        let accepted_bitmap_clone = resume_bitmap.clone().or(accepted_bitmap.clone());
        tokio::spawn(async move {
            let mut pl = pipeline;
            while let Some(ready) = pl.next().await {
                if let Some(ref bitmap) = accepted_bitmap_clone {
                    let byte = ready.index as usize / 8;
                    let bit = ready.index % 8;
                    if byte < bitmap.len() && (bitmap[byte] >> bit) & 1 == 1 {
                        continue; // skip
                    }
                }
                let _ = tx_clone.send(ready).await;
            }
        });
        rx
    };

    let mut rate_limiter = {
        let (_, config) = crate::storage::get_or_create_identity()?;
        RateLimiter::new(config.max_upload_mbps)
    };

    let start_time = Instant::now();
    let mut sent_chunks = 0u32;
    if let Some(bitmap) = resume_bitmap.as_ref().or(accepted_bitmap.as_ref()) {
        for &byte in bitmap {
            sent_chunks += byte.count_ones();
        }
    }

    while let Some(ready) = pipeline_rx.recv().await {
        rate_limiter.throttle(ready.encrypted.len()).await;

        let chunk_msg = ArcMessage::Chunk {
            transfer_id: match &offer {
                ArcMessage::TransferOffer { transfer_id, .. } => *transfer_id,
                _ => [0u8; 16],
            },
            index: ready.index,
            hash: ready.original_hash,
            data: ready.encrypted,
            is_last: ready.is_last,
        };

        let mut retries = 0;
        loop {
            send_msg_stream(&mut send_stream, &chunk_msg).await?;

            // Wait for ChunkAck or ChunkNak
            let ack_msg = recv_msg_stream(&mut recv_stream).await?;
            validate_message_for_state(&ack_msg, &current_state)?;
            if let Some(next) = next_state(&current_state, &ack_msg) {
                current_state = next;
            }

            match ack_msg {
                ArcMessage::ChunkAck { .. } => {
                    break;
                }
                ArcMessage::ChunkNak { retry_count, .. } => {
                    retries += 1;
                    if retries > 5 {
                        return Err(anyhow::anyhow!(
                            "Chunk retransmission limit exceeded (index: {})",
                            ready.index
                        ));
                    }
                    tracing::warn!(
                        index = ready.index,
                        retry_count,
                        "Received ChunkNak, retransmitting chunk"
                    );
                }
                ArcMessage::TransferAbort { reason, .. } => {
                    return Err(anyhow::anyhow!(
                        "Transfer aborted by receiver: {:?}",
                        reason
                    ));
                }
                _ => return Err(anyhow::anyhow!("Expected ChunkAck or ChunkNak")),
            }
        }

        sent_chunks += 1;
        if let Some(ref tx) = progress_tx {
            let _ = tx.send((sent_chunks, chunk_count)).await;
        }
    }

    // Send TransferComplete
    let complete = ArcMessage::TransferComplete {
        transfer_id: match &offer {
            ArcMessage::TransferOffer { transfer_id, .. } => *transfer_id,
            _ => [0u8; 16],
        },
        file_hash: match &offer {
            ArcMessage::TransferOffer { file_hash, .. } => *file_hash,
            _ => [0u8; 32],
        },
        duration_ms: start_time.elapsed().as_millis() as u64,
        wire_bytes: chunker.file_size,
    };
    send_msg_stream(&mut send_stream, &complete).await?;

    // Wait for Goodbye
    current_state = SessionState::IdleReady;
    let goodbye_msg = recv_msg_stream(&mut recv_stream).await?;
    validate_message_for_state(&goodbye_msg, &current_state)?;
    match goodbye_msg {
        ArcMessage::Goodbye { .. } => {}
        _ => return Err(anyhow::anyhow!("Expected Goodbye")),
    }

    println!(
        "File transfer completed successfully over QUIC in {:.2}s!",
        start_time.elapsed().as_secs_f32()
    );
    Ok(())
}

async fn run_quic_stdin_sender_session(
    conn: &iroh::endpoint::Connection,
    offer: ArcMessage,
    session_keys: &crate::crypto::identity::SessionKeys,
    expected_peer_id: [u8; 32],
    progress_tx: Option<mpsc::Sender<(u32, u32)>>,
) -> Result<(), anyhow::Error> {
    let (mut send_stream, mut recv_stream) = conn.open_bi().await?;

    // 1. Hello exchange
    let (identity, _config) = crate::storage::get_or_create_identity()?;
    let hello = ArcMessage::Hello {
        protocol_version: 1,
        device_id: identity.device_id(),
        nonce: rand::random(),
        capabilities: crate::protocol::capability::default_capabilities(),
    };
    send_msg_stream(&mut send_stream, &hello).await?;

    let hello_ack = recv_msg_stream(&mut recv_stream).await?;
    let (peer_device_id, selected_capabilities) = match hello_ack {
        ArcMessage::HelloAck {
            protocol_version,
            device_id,
            selected_capabilities,
            ..
        } => {
            if protocol_version != 1 {
                return Err(anyhow::anyhow!(
                    "Unsupported protocol version: {}",
                    protocol_version
                ));
            }
            (device_id, selected_capabilities)
        }
        _ => return Err(anyhow::anyhow!("Expected HelloAck")),
    };

    if selected_capabilities.is_empty() {
        return Err(anyhow::anyhow!(
            "Capability negotiation failed: peer returned empty capabilities"
        ));
    }

    if peer_device_id != expected_peer_id {
        return Err(anyhow::anyhow!(
            "Unexpected peer device ID: expected {}",
            hex::encode(expected_peer_id)
        ));
    }

    // 2. Receive AuthChallenge
    let challenge_msg = recv_msg_stream(&mut recv_stream).await?;
    let challenge = match challenge_msg {
        ArcMessage::AuthChallenge { challenge } => challenge,
        _ => return Err(anyhow::anyhow!("Expected AuthChallenge")),
    };

    // 3. Send AuthResponse containing signature
    let signature = identity.sign(&challenge);
    let response = ArcMessage::AuthResponse { signature };
    send_msg_stream(&mut send_stream, &response).await?;

    // 4. Wait for AuthOk
    let ok_msg = recv_msg_stream(&mut recv_stream).await?;
    match ok_msg {
        ArcMessage::AuthOk => {}
        ArcMessage::AuthFail { reason } => {
            return Err(anyhow::anyhow!("Authentication failed: {:?}", reason));
        }
        _ => return Err(anyhow::anyhow!("Expected AuthOk or AuthFail")),
    }

    // Send TransferOffer
    send_msg_stream(&mut send_stream, &offer).await?;

    // Wait for TransferAccept
    let accept_msg = recv_msg_stream(&mut recv_stream).await?;
    match accept_msg {
        ArcMessage::TransferAccept { .. } => {}
        ArcMessage::TransferReject { reason, .. } => {
            return Err(anyhow::anyhow!("Transfer rejected by receiver: {}", reason));
        }
        _ => return Err(anyhow::anyhow!("Expected TransferAccept or TransferReject")),
    };

    info!("Stdin transfer accepted over QUIC; starting chunk stream");

    // Create the pipeline
    let session_id = session_keys.session_id;
    let suite = CipherSuite::ChaCha20Poly1305Blake3;
    let worker_count = MachineCapacity::detect().optimal_parallel_chunks(false);
    let mut pipeline = TransferPipeline::new(
        4,
        worker_count,
        CompressionAlgo::None,
        session_id,
        session_keys.sender_key,
        suite,
    );

    // Read chunks in a separate task
    let (hash_tx, hash_rx) = tokio::sync::oneshot::channel::<[u8; 32]>();
    let pipeline_tx = pipeline.clone_tx().expect("pipeline should be open");
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut index = 0u32;
        let mut current_chunk: Option<Vec<u8>> = None;
        let mut buffer = vec![0u8; 1_048_576];
        let mut overall_hasher = blake3::Hasher::new();
        loop {
            match stdin.read(&mut buffer).await {
                Ok(0) => {
                    // EOF reached
                    if let Some(data) = current_chunk.take() {
                        overall_hasher.update(&data);
                        let _ = pipeline_tx
                            .send(RawChunk {
                                index,
                                data,
                                is_last: true,
                            })
                            .await;
                    } else {
                        // Empty stream, send an empty last chunk
                        let _ = pipeline_tx
                            .send(RawChunk {
                                index,
                                data: vec![],
                                is_last: true,
                            })
                            .await;
                    }
                    break;
                }
                Ok(n) => {
                    let next_chunk = buffer[..n].to_vec();
                    if let Some(data) = current_chunk.replace(next_chunk) {
                        overall_hasher.update(&data);
                        let _ = pipeline_tx
                            .send(RawChunk {
                                index,
                                data,
                                is_last: false,
                            })
                            .await;
                        index += 1;
                    }
                }
                Err(_) => {
                    break;
                }
            }
        }
        let final_hash = *overall_hasher.finalize().as_bytes();
        let _ = hash_tx.send(final_hash);
    });
    pipeline.close();

    // Receive processed chunks from pipeline
    let mut pipeline_rx = {
        let (tx, rx) = mpsc::channel(16);
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            let mut pl = pipeline;
            while let Some(ready) = pl.next().await {
                let _ = tx_clone.send(ready).await;
            }
        });
        rx
    };

    let mut rate_limiter = {
        let (_, config) = crate::storage::get_or_create_identity()?;
        RateLimiter::new(config.max_upload_mbps)
    };

    let start_time = Instant::now();
    let mut sent_chunks = 0u32;
    let mut total_wire_bytes = 0u64;

    while let Some(ready) = pipeline_rx.recv().await {
        rate_limiter.throttle(ready.encrypted.len()).await;
        total_wire_bytes += ready.encrypted.len() as u64;

        let chunk_msg = ArcMessage::Chunk {
            transfer_id: match &offer {
                ArcMessage::TransferOffer { transfer_id, .. } => *transfer_id,
                _ => [0u8; 16],
            },
            index: ready.index,
            hash: ready.original_hash,
            data: ready.encrypted,
            is_last: ready.is_last,
        };

        send_msg_stream(&mut send_stream, &chunk_msg).await?;

        // Wait for ChunkAck
        let ack_msg = recv_msg_stream(&mut recv_stream).await?;
        match ack_msg {
            ArcMessage::ChunkAck { .. } => {}
            ArcMessage::TransferAbort { reason, .. } => {
                return Err(anyhow::anyhow!(
                    "Transfer aborted by receiver: {:?}",
                    reason
                ));
            }
            _ => return Err(anyhow::anyhow!("Expected ChunkAck")),
        }

        sent_chunks += 1;
        if let Some(ref tx) = progress_tx {
            let _ = tx.send((sent_chunks, 0)).await;
        }
    }

    let file_hash = hash_rx.await.unwrap_or([0u8; 32]);

    // Send TransferComplete
    let complete = ArcMessage::TransferComplete {
        transfer_id: match &offer {
            ArcMessage::TransferOffer { transfer_id, .. } => *transfer_id,
            _ => [0u8; 16],
        },
        file_hash,
        duration_ms: start_time.elapsed().as_millis() as u64,
        wire_bytes: total_wire_bytes,
    };
    send_msg_stream(&mut send_stream, &complete).await?;

    // Wait for Goodbye
    let goodbye_msg = recv_msg_stream(&mut recv_stream).await?;
    match goodbye_msg {
        ArcMessage::Goodbye { .. } => {}
        _ => return Err(anyhow::anyhow!("Expected Goodbye")),
    }

    println!(
        "Stdin transfer completed successfully over QUIC in {:.2}s!",
        start_time.elapsed().as_secs_f32()
    );
    Ok(())
}

pub async fn run_sender(
    path_str: &str,
    phrase: &str,
    relay_url: &str,
    share_mode: bool,
    clipboard_mode: bool,
    progress_tx: Option<mpsc::Sender<(u32, u32)>>,
) -> Result<(), anyhow::Error> {
    let path = Path::new(path_str);
    if !path.exists() {
        return Err(anyhow::anyhow!("file not found: {}", path_str));
    }

    // 1. Generate pairing/signaling key from phrase using PBKDF2
    let phrase_seed = crate::crypto::derive_key_from_phrase(phrase);
    let room_id = hex::encode(blake3::hash(&phrase_seed).as_bytes());

    // Load or create local device identity
    let (identity, config) = crate::storage::get_or_create_identity()?;

    // Load secret key for Iroh
    let secret_key_bytes = identity.secret_bytes();
    let secret_key = iroh::SecretKey::from_bytes(&secret_key_bytes);

    // Initialize Iroh endpoint
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret_key)
        .alpns(vec![b"arc/1".to_vec()])
        .bind()
        .await?;

    // Wait until endpoint has contacted the relay server to ensure our_node_addr contains routing info.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), endpoint.online()).await;
    let our_node_addr = endpoint.addr();
    info!(?our_node_addr, "Sender local node address");

    let our_nonce: [u8; 32] = rand::random();
    let our_ephemeral = EphemeralKeyPair::generate();
    let mut sig_input = Vec::with_capacity(64);
    sig_input.extend_from_slice(&our_nonce);
    sig_input.extend_from_slice(&our_ephemeral.public.to_bytes());
    let sig = identity.sign(&sig_input);
    let handshake_out = HandshakePayload {
        device_id: identity.device_id(),
        device_name: config.device_name.clone(),
        node_addr: our_node_addr,
        ephemeral_public: our_ephemeral.public.to_bytes(),
        nonce: our_nonce,
        signature: Some(sig.to_vec()),
    };

    let disable_mdns = std::env::var("ARC_DISABLE_MDNS").is_ok();
    let mut local_relay = None;
    let mut local_ws_write = None;
    let mut local_ws_read = None;

    if !disable_mdns {
        // Start local relay and register via mDNS
        let (local_port, shutdown_tx) = super::transport::start_local_relay().await?;
        let daemon = mdns_sd::ServiceDaemon::new()?;
        let local_ips = crate::transfer::discovery::get_local_ips();
        let ip_to_use = local_ips
            .first()
            .copied()
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
        let service_type = "_arc-transfer._tcp.local.";
        let instance_name = room_id[..32].to_string();
        let host_name = format!("{}.local.", instance_name);
        let service_info = mdns_sd::ServiceInfo::new(
            service_type,
            &instance_name,
            &host_name,
            ip_to_use,
            local_port,
            None,
        )?;
        daemon.register(service_info.clone())?;
        local_relay = Some((local_port, shutdown_tx, daemon, service_info));

        let local_relay_url = format!("ws://127.0.0.1:{}/ws", local_port);
        let local_ws = crate::connect_relay(&local_relay_url).await?;
        let (w, r) = local_ws.split();
        local_ws_write = Some(w);
        local_ws_read = Some(r);
    }

    // Connect to public relay in parallel
    let public_ws = crate::connect_relay(relay_url).await;

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
        max_members: if share_mode { Some(10) } else { Some(2) },
    };
    let join_json = serde_json::to_string(&join_req)?;
    if let Some(ref mut w) = local_ws_write {
        w.send(Message::Text(join_json.clone().into())).await?;
    }
    if let Some(ref mut w) = public_ws_write {
        let _ = w.send(Message::Text(join_json.into())).await;
    }

    println!("Waiting for receiver to join room...");

    let mut receiver_handshake: Option<HandshakePayload> = None;
    let mut local_handshake_sent = false;
    let mut public_handshake_sent = false;

    loop {
        tokio::select! {
            local_msg = async {
                if let Some(ref mut r) = local_ws_read {
                    r.next().await
                } else {
                    futures_util::future::pending().await
                }
            } => {
                if let Some(msg_res) = local_msg {
                    let msg = msg_res?;
                    if let Message::Text(text) = msg {
                        if let Ok(relay_msg) = serde_json::from_str::<WsRelayMessage>(&text) {
                            match relay_msg {
                                WsRelayMessage::Joined { member_count, .. } | WsRelayMessage::RoomMemberCount { count: member_count, .. } => {
                                    if member_count == 2 && !local_handshake_sent {
                                        let handshake_bytes = serde_json::to_vec(&handshake_out)?;
                                        let signal_data = encrypt_signal(&phrase_seed, &handshake_bytes)?;
                                        let sig_req = WsSignal {
                                            r#type: "signal",
                                            room_id: room_id.clone(),
                                            data: signal_data,
                                        };
                                        let sig_json = serde_json::to_string(&sig_req)?;
                                        if let Some(ref mut w) = local_ws_write {
                                            w.send(Message::Text(sig_json.into())).await?;
                                        }
                                        local_handshake_sent = true;
                                    }
                                }
                                WsRelayMessage::Signal { data } => {
                                    if let Ok(decrypted) = decrypt_signal(&phrase_seed, &data) {
                                        if let Ok(payload) = serde_json::from_slice::<HandshakePayload>(&decrypted) {
                                            receiver_handshake = Some(payload);
                                            break;
                                        }
                                    }
                                }
                                _ => {}
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
                                WsRelayMessage::Joined { member_count, .. } | WsRelayMessage::RoomMemberCount { count: member_count, .. } => {
                                    if member_count > 2 && !share_mode {
                                        return Err(anyhow::anyhow!("Relay MITM detected (members > 2)"));
                                    }
                                    if member_count == 2 && !public_handshake_sent {
                                        let handshake_bytes = serde_json::to_vec(&handshake_out)?;
                                        let signal_data = encrypt_signal(&phrase_seed, &handshake_bytes)?;
                                        let sig_req = WsSignal {
                                            r#type: "signal",
                                            room_id: room_id.clone(),
                                            data: signal_data,
                                        };
                                        let sig_json = serde_json::to_string(&sig_req)?;
                                        if let Some(ref mut w) = public_ws_write {
                                            let _ = w.send(Message::Text(sig_json.into())).await;
                                        }
                                        public_handshake_sent = true;
                                    }
                                }
                                WsRelayMessage::Signal { data } => {
                                    if let Ok(decrypted) = decrypt_signal(&phrase_seed, &data) {
                                        if let Ok(payload) = serde_json::from_slice::<HandshakePayload>(&decrypted) {
                                            receiver_handshake = Some(payload);
                                            break;
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                } else {
                    break;
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

    println!("Receiver '{}' connected.", rx_payload.device_name);

    // Perform DH key exchange
    let rx_ephemeral_pub = x25519_dalek::PublicKey::from(rx_payload.ephemeral_public);
    let session_keys =
        our_ephemeral.derive_session_keys(&rx_ephemeral_pub, &our_nonce, &rx_payload.nonce);

    // Save as paired peer if not already
    let mut updated_config = config.clone();
    if !updated_config
        .peers
        .iter()
        .any(|p| p.device_id == rx_payload.device_id)
    {
        updated_config.peers.push(crate::storage::PeerInfo {
            name: rx_payload.device_name.clone(),
            device_id: rx_payload.device_id,
        });
        let _ = crate::storage::save_config(&updated_config);
    }

    println!("Sender: Waiting for incoming QUIC connection over Iroh...");
    let incoming = tokio::time::timeout(std::time::Duration::from_secs(30), endpoint.accept())
        .await
        .map_err(|_| anyhow::anyhow!("Timeout waiting for incoming connection"))?
        .ok_or_else(|| anyhow::anyhow!("Iroh listener closed"))?;
    let conn = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        incoming.await
    })
    .await
    .map_err(|_| anyhow::anyhow!("Timeout establishing connection"))??;
    println!("Sender: QUIC connection established over Iroh.");

    // Now start the transfer session!
    let is_dir = path.is_dir();
    let (_temp_path, offer_path) = if is_dir {
        let temp_file = tempfile::NamedTempFile::new()?;
        let (file, temp_path) = temp_file.into_parts();
        let path_buf = temp_path.to_path_buf();
        let mut archive = tar::Builder::new(file);
        let dir_name = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("Invalid directory path (no filename)"))?
            .to_string_lossy()
            .to_string();
        archive.append_dir_all(&dir_name, path)?;
        archive.finish()?;
        (Some(temp_path), path_buf)
    } else {
        (None, path.to_path_buf())
    };

    let chunker = AdaptiveChunker::new(&offer_path, false)?;
    let file_size = chunker.file_size;
    let chunk_count = chunker.chunk_count;
    let chunk_size = chunker.config.chunk_size;
    let compression = chunker.config.compression;

    // Calculate file hashes
    info!("Calculating file hash...");
    let path_clone = path.to_path_buf();
    let offer_path_clone = offer_path.clone();
    let file_hash = tokio::task::spawn_blocking(move || {
        if is_dir {
            crate::crypto::hash::blake3_hash_dir(&path_clone)
        } else {
            crate::crypto::hash::blake3_hash_file(&offer_path_clone)
        }
    })
    .await??;
    let partial_hash = crate::crypto::hash::arc_fast_hash(&offer_path)?;

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid file path (no filename)"))?
        .to_string_lossy()
        .to_string();
    let transfer_id = Uuid::new_v4();
    let offer = ArcMessage::TransferOffer {
        transfer_id: *transfer_id.as_bytes(),
        kind: if clipboard_mode {
            TransferKind::Clipboard
        } else if is_dir {
            TransferKind::Directory
        } else {
            TransferKind::File
        },
        file_name: file_name.clone(),
        total_size: file_size,
        chunk_count,
        chunk_size,
        file_hash,
        partial_hash,
        compression,
    };

    let session_res = run_quic_sender_session(
        &conn,
        &offer_path,
        offer.clone(),
        &chunker,
        &session_keys,
        rx_payload.device_id,
        None,
        progress_tx.clone(),
    )
    .await;

    if let Some((_, shutdown_tx, daemon, service_info)) = local_relay {
        let _ = shutdown_tx.send(());
        let _ = daemon.unregister(service_info.get_fullname());
    }

    session_res?;
    Ok(())
}

pub async fn run_stdin_sender(
    name: &str,
    phrase: &str,
    relay_url: &str,
    progress_tx: Option<mpsc::Sender<(u32, u32)>>,
) -> Result<(), anyhow::Error> {
    let phrase_seed = crate::crypto::derive_key_from_phrase(phrase);
    let room_id = hex::encode(blake3::hash(&phrase_seed).as_bytes());

    // Load or create local device identity
    let (identity, config) = crate::storage::get_or_create_identity()?;

    // Load secret key for Iroh
    let secret_key_bytes = identity.secret_bytes();
    let secret_key = iroh::SecretKey::from_bytes(&secret_key_bytes);

    // Initialize Iroh endpoint
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret_key)
        .alpns(vec![b"arc/1".to_vec()])
        .bind()
        .await?;

    // Wait until endpoint has contacted the relay server to ensure our_node_addr contains routing info.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), endpoint.online()).await;
    let our_node_addr = endpoint.addr();
    info!(?our_node_addr, "Stdin sender local node address");

    let our_nonce: [u8; 32] = rand::random();
    let our_ephemeral = EphemeralKeyPair::generate();
    let mut sig_input = Vec::with_capacity(64);
    sig_input.extend_from_slice(&our_nonce);
    sig_input.extend_from_slice(&our_ephemeral.public.to_bytes());
    let sig = identity.sign(&sig_input);
    let handshake_out = HandshakePayload {
        device_id: identity.device_id(),
        device_name: config.device_name.clone(),
        node_addr: our_node_addr,
        ephemeral_public: our_ephemeral.public.to_bytes(),
        nonce: our_nonce,
        signature: Some(sig.to_vec()),
    };

    // Start local relay and register via mDNS
    let (local_port, shutdown_tx) = super::transport::start_local_relay().await?;
    let daemon = mdns_sd::ServiceDaemon::new()?;
    let local_ips = crate::transfer::discovery::get_local_ips();
    let ip_to_use = local_ips
        .first()
        .copied()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
    let service_type = "_arc-transfer._tcp.local.";
    let instance_name = room_id[..32].to_string();
    let host_name = format!("{}.local.", instance_name);
    let service_info = mdns_sd::ServiceInfo::new(
        service_type,
        &instance_name,
        &host_name,
        ip_to_use,
        local_port,
        None,
    )?;
    daemon.register(service_info.clone())?;
    let local_relay = Some((local_port, shutdown_tx, daemon, service_info));

    let local_relay_url = format!("ws://127.0.0.1:{}/ws", local_port);
    let local_ws = crate::connect_relay(&local_relay_url).await?;

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
    local_ws_write
        .send(Message::Text(join_json.clone().into()))
        .await?;
    if let Some(ref mut w) = public_ws_write {
        let _ = w.send(Message::Text(join_json.into())).await;
    }

    println!("Waiting for receiver to join room...");

    let mut receiver_handshake: Option<HandshakePayload> = None;
    let mut local_handshake_sent = false;
    let mut public_handshake_sent = false;

    loop {
        tokio::select! {
            local_msg = local_ws_read.next() => {
                if let Some(msg_res) = local_msg {
                    let msg = msg_res?;
                    if let Message::Text(text) = msg {
                        if let Ok(relay_msg) = serde_json::from_str::<WsRelayMessage>(&text) {
                            match relay_msg {
                                WsRelayMessage::Joined { member_count, .. } | WsRelayMessage::RoomMemberCount { count: member_count, .. } => {
                                    if member_count == 2 && !local_handshake_sent {
                                        let handshake_bytes = serde_json::to_vec(&handshake_out)?;
                                        let signal_data = encrypt_signal(&phrase_seed, &handshake_bytes)?;
                                        let sig_req = WsSignal {
                                            r#type: "signal",
                                            room_id: room_id.clone(),
                                            data: signal_data,
                                        };
                                        let sig_json = serde_json::to_string(&sig_req)?;
                                        local_ws_write.send(Message::Text(sig_json.into())).await?;
                                        local_handshake_sent = true;
                                    }
                                }
                                WsRelayMessage::Signal { data } => {
                                    if let Ok(decrypted) = decrypt_signal(&phrase_seed, &data) {
                                        if let Ok(payload) = serde_json::from_slice::<HandshakePayload>(&decrypted) {
                                            receiver_handshake = Some(payload);
                                            break;
                                        }
                                    }
                                }
                                _ => {}
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
                                WsRelayMessage::Joined { member_count, .. } | WsRelayMessage::RoomMemberCount { count: member_count, .. } => {
                                    if member_count > 2 {
                                        return Err(anyhow::anyhow!("Relay MITM detected (members > 2)"));
                                    }
                                    if member_count == 2 && !public_handshake_sent {
                                        let handshake_bytes = serde_json::to_vec(&handshake_out)?;
                                        let signal_data = encrypt_signal(&phrase_seed, &handshake_bytes)?;
                                        let sig_req = WsSignal {
                                            r#type: "signal",
                                            room_id: room_id.clone(),
                                            data: signal_data,
                                        };
                                        let sig_json = serde_json::to_string(&sig_req)?;
                                        if let Some(ref mut w) = public_ws_write {
                                            let _ = w.send(Message::Text(sig_json.into())).await;
                                        }
                                        public_handshake_sent = true;
                                    }
                                }
                                WsRelayMessage::Signal { data } => {
                                    if let Ok(decrypted) = decrypt_signal(&phrase_seed, &data) {
                                        if let Ok(payload) = serde_json::from_slice::<HandshakePayload>(&decrypted) {
                                            receiver_handshake = Some(payload);
                                            break;
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                } else {
                    break;
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

    println!("Receiver '{}' connected.", rx_payload.device_name);

    // Perform DH key exchange
    let rx_ephemeral_pub = x25519_dalek::PublicKey::from(rx_payload.ephemeral_public);
    let session_keys =
        our_ephemeral.derive_session_keys(&rx_ephemeral_pub, &our_nonce, &rx_payload.nonce);

    // Save as paired peer if not already
    let mut updated_config = config.clone();
    if !updated_config
        .peers
        .iter()
        .any(|p| p.device_id == rx_payload.device_id)
    {
        updated_config.peers.push(crate::storage::PeerInfo {
            name: rx_payload.device_name.clone(),
            device_id: rx_payload.device_id,
        });
        let _ = crate::storage::save_config(&updated_config);
    }

    // Now start the transfer session!
    let transfer_id = Uuid::new_v4();
    let safe_name = Path::new(name)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let offer = ArcMessage::TransferOffer {
        transfer_id: *transfer_id.as_bytes(),
        kind: TransferKind::Stdin,
        file_name: safe_name,
        total_size: 0,
        chunk_count: 0,
        chunk_size: 1_048_576,
        file_hash: [0u8; 32],
        partial_hash: [0u8; 32],
        compression: CompressionAlgo::None,
    };

    println!("Sender: Waiting for incoming QUIC connection over Iroh...");
    let incoming = tokio::time::timeout(std::time::Duration::from_secs(120), endpoint.accept())
        .await
        .map_err(|_| anyhow::anyhow!("Timeout waiting for incoming connection"))?
        .ok_or_else(|| anyhow::anyhow!("Iroh listener closed"))?;
    let conn = tokio::time::timeout(std::time::Duration::from_secs(120), async {
        incoming.await
    })
    .await
    .map_err(|_| anyhow::anyhow!("Timeout establishing connection"))??;
    println!("Sender: QUIC connection established over Iroh.");

    let session_res = run_quic_stdin_sender_session(
        &conn,
        offer.clone(),
        &session_keys,
        rx_payload.device_id,
        progress_tx.clone(),
    )
    .await;

    if let Some((_, shutdown_tx, daemon, service_info)) = local_relay {
        let _ = shutdown_tx.send(());
        let _ = daemon.unregister(service_info.get_fullname());
    }

    session_res?;
    Ok(())
}
