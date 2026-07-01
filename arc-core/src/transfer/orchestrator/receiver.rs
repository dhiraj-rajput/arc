use std::fs;
use std::path::Path;

use futures_util::{SinkExt, StreamExt};
use serde_json;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::Message;

use crate::compression::decompress_with_limit;
use crate::crypto::cipher::{CipherSuite, Direction, build_nonce, decrypt_chunk};
use crate::crypto::identity::EphemeralKeyPair;
use crate::protocol::messages::{ArcMessage, TransferKind};

use super::transport::{
    HandshakePayload, WsJoin, WsRelayMessage, WsSignal, decrypt_signal, encrypt_signal,
    recv_msg_stream, send_msg_stream,
};

async fn run_quic_receiver_session(
    conn: &iroh::endpoint::Connection,
    output_dir: &str,
    session_keys: &crate::crypto::identity::SessionKeys,
    expected_peer_id: [u8; 32],
    progress_tx: Option<mpsc::Sender<(u32, u32)>>,
    stdout_tx: Option<mpsc::Sender<Vec<u8>>>,
    sender_name: &str,
) -> Result<Option<String>, anyhow::Error> {
    let (mut send_stream, mut recv_stream) = conn.accept_bi().await?;
    use crate::protocol::state::{SessionState, next_state, validate_message_for_state};
    let mut current_state = SessionState::Idle;

    // 1. Hello exchange
    let (identity, _config) = crate::storage::get_or_create_identity()?;
    let hello_msg = recv_msg_stream(&mut recv_stream).await?;
    validate_message_for_state(&hello_msg, &current_state)?;
    current_state = next_state(&current_state, &hello_msg).unwrap_or(current_state);
    tracing::debug!("Receiver: Protocol state transitioned to {}", current_state);

    let (peer_device_id, peer_capabilities) = match hello_msg {
        ArcMessage::Hello {
            protocol_version,
            device_id,
            capabilities,
            ..
        } => {
            if protocol_version != 1 {
                let fail = ArcMessage::AuthFail {
                    reason: crate::protocol::messages::AuthFailReason::VersionMismatch,
                };
                let _ = send_msg_stream(&mut send_stream, &fail).await;
                return Err(anyhow::anyhow!(
                    "Unsupported protocol version: {}",
                    protocol_version
                ));
            }
            (device_id, capabilities)
        }
        _ => return Err(anyhow::anyhow!("Expected Hello")),
    };

    if peer_device_id != expected_peer_id {
        let fail = ArcMessage::AuthFail {
            reason: crate::protocol::messages::AuthFailReason::DeviceNotPaired,
        };
        let _ = send_msg_stream(&mut send_stream, &fail).await;
        return Err(anyhow::anyhow!(
            "Unexpected peer device ID: expected {}",
            hex::encode(expected_peer_id)
        ));
    }

    // Negotiate capabilities (empty intersection returns NegotiationError::EmptyIntersection)
    let our_caps = crate::protocol::capability::default_capabilities();
    let selected_capabilities =
        match crate::protocol::capability::negotiate_capabilities(&our_caps, &peer_capabilities) {
            Ok(caps) => caps,
            Err(_) => {
                let fail = ArcMessage::AuthFail {
                    reason: crate::protocol::messages::AuthFailReason::NoCommonSuite,
                };
                let _ = send_msg_stream(&mut send_stream, &fail).await;
                return Err(anyhow::anyhow!(
                    "Capability negotiation failed: no common capabilities"
                ));
            }
        };

    // Send HelloAck
    let hello_ack = ArcMessage::HelloAck {
        protocol_version: 1,
        device_id: identity.device_id(),
        nonce: rand::random(),
        selected_capabilities,
    };
    send_msg_stream(&mut send_stream, &hello_ack).await?;

    // 2. Send AuthChallenge
    let challenge: [u8; 32] = rand::random();
    let challenge_msg = ArcMessage::AuthChallenge { challenge };
    send_msg_stream(&mut send_stream, &challenge_msg).await?;
    current_state = SessionState::Authenticating;

    // 3. Receive AuthResponse
    let response_msg = recv_msg_stream(&mut recv_stream).await?;
    validate_message_for_state(&response_msg, &current_state)?;

    let signature = match response_msg {
        ArcMessage::AuthResponse { signature } => signature,
        _ => {
            let fail = ArcMessage::AuthFail {
                reason: crate::protocol::messages::AuthFailReason::ProtocolError,
            };
            let _ = send_msg_stream(&mut send_stream, &fail).await;
            return Err(anyhow::anyhow!("Expected AuthResponse"));
        }
    };

    // 4. Verify signature
    if crate::crypto::identity::DeviceIdentity::verify_peer_signature(
        &peer_device_id,
        &challenge,
        &signature,
    )
    .is_err()
    {
        let fail = ArcMessage::AuthFail {
            reason: crate::protocol::messages::AuthFailReason::BadSignature,
        };
        let _ = send_msg_stream(&mut send_stream, &fail).await;
        return Err(anyhow::anyhow!("Authentication failed: BadSignature"));
    }

    // Send AuthOk
    let ok = ArcMessage::AuthOk;
    send_msg_stream(&mut send_stream, &ok).await?;
    current_state = SessionState::Negotiating;

    // Wait for TransferOffer
    let offer_msg = recv_msg_stream(&mut recv_stream).await?;
    validate_message_for_state(&offer_msg, &current_state)?;

    let (
        transfer_id,
        file_name,
        total_size,
        chunk_count,
        chunk_size,
        compression,
        file_hash,
        partial_hash,
        kind,
    ) = match &offer_msg {
        ArcMessage::TransferOffer {
            transfer_id,
            file_name,
            total_size,
            chunk_count,
            chunk_size,
            compression,
            file_hash,
            partial_hash,
            kind,
            ..
        } => (
            *transfer_id,
            file_name.clone(),
            *total_size,
            *chunk_count,
            *chunk_size,
            *compression,
            *file_hash,
            *partial_hash,
            kind.clone(),
        ),
        _ => return Err(anyhow::anyhow!("Expected TransferOffer")),
    };

    println!(
        "Incoming transfer over QUIC: '{}' ({} bytes, {} chunks)",
        file_name, total_size, chunk_count
    );

    use std::io::IsTerminal;

    if stdout_tx.is_none() && std::io::stdin().is_terminal() {
        let size_str = if total_size > 1024 * 1024 * 1024 {
            format!("{:.2} GB", total_size as f64 / (1024.0 * 1024.0 * 1024.0))
        } else if total_size > 1024 * 1024 {
            format!("{:.2} MB", total_size as f64 / (1024.0 * 1024.0))
        } else {
            format!("{} bytes", total_size)
        };
        let prompt_msg = format!(
            "Do you want to accept transfer of '{}' ({}) from '{}'?",
            file_name, size_str, sender_name
        );
        let accept_transfer = dialoguer::Confirm::new()
            .with_prompt(&prompt_msg)
            .default(true)
            .interact()?;

        if !accept_transfer {
            let abort = ArcMessage::TransferAbort {
                transfer_id,
                reason: crate::protocol::messages::AbortReason::UserCancelled,
            };
            let _ = send_msg_stream(&mut send_stream, &abort).await;
            return Err(anyhow::anyhow!("Transfer rejected by user"));
        }
    }

    // Resolve absolute safe output path to prevent path traversal (SEC-2)
    let output_path = match crate::security::resolve_safe_path(Path::new(output_dir), &file_name) {
        Ok(path) => path,
        Err(e) => {
            let abort = ArcMessage::TransferAbort {
                transfer_id,
                reason: crate::protocol::messages::AbortReason::ProtocolError(format!(
                    "Invalid path: {}",
                    e
                )),
            };
            let _ = send_msg_stream(&mut send_stream, &abort).await;
            return Err(anyhow::anyhow!(
                "Path traversal or invalid path detected: {}",
                e
            ));
        }
    };
    let safe_name = output_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();

    let mut resume_state = match crate::transfer::resume::ResumeState::load_from_disk(
        &transfer_id,
        file_hash,
        chunk_count,
    ) {
        Ok(state) => {
            println!(
                "Resuming transfer from chunk {}/{}...",
                state.received_count(),
                chunk_count
            );
            state
        }
        Err(_) => {
            // Deduplication Check: Skip transfer if file already exists with matching size and hashes
            if output_path.exists() && output_path.is_file() {
                if let Ok(meta) = std::fs::metadata(&output_path) {
                    if meta.len() == total_size {
                        if let Ok(local_partial) = crate::crypto::hash::arc_fast_hash(&output_path)
                        {
                            if local_partial == partial_hash {
                                if let Ok(local_full) =
                                    crate::crypto::hash::blake3_hash_file(&output_path)
                                {
                                    if local_full == file_hash {
                                        println!(
                                            "File '{}' is already present and verified. Skipping transfer (deduplication).",
                                            safe_name
                                        );
                                        let mut state = crate::transfer::resume::ResumeState::new(
                                            chunk_count,
                                            file_hash,
                                        );
                                        for idx in 0..chunk_count {
                                            state.mark_received(idx);
                                        }
                                        state
                                    } else {
                                        crate::transfer::resume::ResumeState::new(
                                            chunk_count,
                                            file_hash,
                                        )
                                    }
                                } else {
                                    crate::transfer::resume::ResumeState::new(
                                        chunk_count,
                                        file_hash,
                                    )
                                }
                            } else {
                                crate::transfer::resume::ResumeState::new(chunk_count, file_hash)
                            }
                        } else {
                            crate::transfer::resume::ResumeState::new(chunk_count, file_hash)
                        }
                    } else {
                        crate::transfer::resume::ResumeState::new(chunk_count, file_hash)
                    }
                } else {
                    crate::transfer::resume::ResumeState::new(chunk_count, file_hash)
                }
            } else {
                crate::transfer::resume::ResumeState::new(chunk_count, file_hash)
            }
        }
    };

    let resume_bitmap = if resume_state.received_count() > 0 {
        Some(resume_state.to_bitmap())
    } else {
        None
    };

    // Send TransferAccept
    let accept = ArcMessage::TransferAccept {
        transfer_id,
        resume_bitmap,
    };
    send_msg_stream(&mut send_stream, &accept).await?;
    current_state = SessionState::Transferring;

    println!("Accept sent over QUIC. Receiving chunks...");

    let is_directory = matches!(kind, TransferKind::Directory);
    let is_clipboard = matches!(kind, TransferKind::Clipboard);
    let (temp_file_path, mut file) = if (is_directory || is_clipboard) && stdout_tx.is_none() {
        let temp_file = tempfile::NamedTempFile::new()?;
        let (file, temp_path) = temp_file.into_parts();
        let f = tokio::fs::File::from_std(file);
        (Some(temp_path), Some(f))
    } else {
        let f = if stdout_tx.is_none() {
            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let is_resuming = resume_state.received_count() > 0;
            let f = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(!is_resuming)
                .open(&output_path)
                .await?;
            if total_size > 0 {
                f.set_len(total_size).await?;
            }
            Some(f)
        } else {
            None
        };
        (None, f)
    };

    let mut received_chunks = resume_state.received_count();
    let mut message_index = 0u32;
    let session_id = session_keys.session_id;
    let mut overall_hasher = blake3::Hasher::new();

    loop {
        let chunk_msg = recv_msg_stream(&mut recv_stream).await?;
        validate_message_for_state(&chunk_msg, &current_state)?;
        if let Some(next) = next_state(&current_state, &chunk_msg) {
            current_state = next;
        }

        match chunk_msg {
            ArcMessage::Chunk {
                index,
                hash,
                data: enc_data,
                is_last,
                ..
            } => {
                let nonce = build_nonce(session_id, message_index, Direction::ToReceiver);
                message_index += 1;

                let suite = CipherSuite::ChaCha20Poly1305Blake3;
                let decrypted_data =
                    decrypt_chunk(&session_keys.sender_key, &nonce, &enc_data, suite)?;
                let decompressed = decompress_with_limit(
                    &decrypted_data,
                    compression,
                    (chunk_size as usize).max(1024 * 1024) * 2,
                )?;

                let chunk_hash = crate::crypto::hash::blake3_hash_parallel(&decompressed);
                if chunk_hash != hash {
                    let nak = ArcMessage::ChunkNak {
                        transfer_id,
                        index,
                        retry_count: 0,
                    };
                    send_msg_stream(&mut send_stream, &nak).await?;
                    tracing::warn!(index, "chunk hash mismatch over QUIC, sent ChunkNak");
                    continue;
                }

                overall_hasher.update(&decompressed);

                if let Some(ref mut f) = file {
                    use tokio::io::AsyncSeekExt;
                    use tokio::io::AsyncWriteExt;
                    let offset = index as u64 * chunk_size as u64;
                    f.seek(std::io::SeekFrom::Start(offset)).await?;
                    f.write_all(&decompressed).await?;
                } else if let Some(ref tx) = stdout_tx {
                    let _ = tx.send(decompressed).await;
                }

                received_chunks += 1;
                resume_state.mark_received(index);

                // Batch save to disk to reduce disk I/O overhead
                if index % 10 == 0 || is_last || received_chunks == chunk_count {
                    let _ = resume_state.save_to_disk(&transfer_id);
                }

                if let Some(ref tx) = progress_tx {
                    let _ = tx.send((received_chunks, chunk_count)).await;
                }

                let ack = ArcMessage::ChunkAck { transfer_id, index };
                send_msg_stream(&mut send_stream, &ack).await?;

                if is_last {
                    // Handled when TransferComplete arrives
                }
            }
            ArcMessage::TransferComplete {
                file_hash: complete_hash,
                ..
            } => {
                let _ = crate::transfer::resume::ResumeState::delete_from_disk(&transfer_id);
                let mut clipboard_content = None;
                let has_file = file.is_some();
                if let Some(mut f) = file.take() {
                    use tokio::io::AsyncWriteExt;
                    f.flush().await?;
                    f.sync_all().await?;
                    drop(f);
                }

                if has_file {
                    if is_directory {
                        if let Some(ref tp) = temp_file_path {
                            println!("Unpacking directory to {:?}...", output_dir);
                            let file = std::fs::File::open(tp)?;
                            crate::security::safe_unpack_tar(file, Path::new(output_dir))?;
                            println!(
                                "Directory unpacked successfully! Running folder Merkle forest verification..."
                            );

                            let unpacked_dir_path = Path::new(output_dir).join(&file_name);
                            let dir_hash =
                                crate::crypto::hash::blake3_hash_dir(&unpacked_dir_path)?;
                            if dir_hash != complete_hash {
                                return Err(anyhow::anyhow!(
                                    "Directory Merkle forest verification failed! Directory contents do not match expected root."
                                ));
                            }
                            println!("Directory Merkle forest verification successful!");
                            let _ = std::fs::remove_file(tp);
                        }
                    } else {
                        let hash_path: &Path = if let Some(ref tp) = temp_file_path {
                            tp.as_ref()
                        } else {
                            &output_path
                        };
                        let final_hash = crate::crypto::hash::blake3_hash_file(hash_path)?;
                        if final_hash != complete_hash {
                            return Err(anyhow::anyhow!("Final file hash mismatch!"));
                        }

                        if let Some(ref tp) = temp_file_path {
                            if is_clipboard {
                                let text = std::fs::read_to_string(tp)?;
                                clipboard_content = Some(text);
                                let _ = std::fs::remove_file(tp);
                            }
                        } else {
                            println!("File verified successfully! Saved to {:?}", output_path);
                        }
                    }
                } else {
                    let final_hash = *overall_hasher.finalize().as_bytes();
                    if final_hash != complete_hash {
                        return Err(anyhow::anyhow!("Final file hash mismatch!"));
                    }
                    println!("Stream verified successfully!");
                }

                let goodbye = ArcMessage::Goodbye { reason: None };
                send_msg_stream(&mut send_stream, &goodbye).await?;
                use tokio::io::AsyncWriteExt;
                let _ = send_stream.shutdown().await;
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                return Ok(clipboard_content);
            }
            ArcMessage::TransferAbort { reason, .. } => {
                return Err(anyhow::anyhow!("Transfer aborted by sender: {:?}", reason));
            }
            _ => return Err(anyhow::anyhow!("Unexpected message during transfer")),
        }
    }
}

pub async fn run_receiver(
    output_dir: &str,
    phrase: &str,
    relay_url: &str,
    progress_tx: Option<mpsc::Sender<(u32, u32)>>,
    stdout_tx: Option<mpsc::Sender<Vec<u8>>>,
) -> Result<Option<String>, anyhow::Error> {
    let phrase_seed = crate::crypto::derive_key_from_phrase(phrase);
    let room_id = hex::encode(blake3::hash(&phrase_seed).as_bytes());

    let (identity, config) = crate::storage::get_or_create_identity()?;

    // Load secret key for Iroh
    let secret_key_bytes = identity.secret_bytes();
    let secret_key = iroh::SecretKey::from_bytes(&secret_key_bytes);

    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .secret_key(secret_key)
        .alpns(vec![b"arc/1".to_vec()])
        .bind()
        .await?;

    // Wait until endpoint has contacted the relay server to ensure our_node_addr contains routing info.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), endpoint.online()).await;
    let our_node_addr = endpoint.addr();
    println!("Receiver: our_node_addr = {:?}", our_node_addr);

    let disable_mdns = std::env::var("ARC_DISABLE_MDNS").is_ok();
    let mut resolved_addr = None;
    if !disable_mdns {
        println!("Scanning local network for sender (mDNS)...");
        if let Ok(daemon) = mdns_sd::ServiceDaemon::new() {
            let service_type = "_arc-transfer._tcp.local.";
            if let Ok(receiver) = daemon.browse(service_type) {
                let start = std::time::Instant::now();
                let timeout = std::time::Duration::from_millis(1000);
                while start.elapsed() < timeout {
                    if let Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) =
                        receiver.recv_timeout(std::time::Duration::from_millis(100))
                    {
                        if info.get_fullname().contains(&room_id[..32]) {
                            let port = info.get_port();
                            if let Some(ip) = info.get_addresses().iter().next() {
                                resolved_addr =
                                    Some(std::net::SocketAddr::new(ip.to_ip_addr(), port));
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    let ws_stream = if let Some(addr) = resolved_addr {
        println!("mDNS peer found! Establishing direct local connection...");
        let local_relay_url = format!("ws://{}:{}/ws", addr.ip(), addr.port());
        crate::connect_relay(&local_relay_url).await?
    } else {
        println!(
            "mDNS peer not found locally. Connecting to public relay at {}...",
            relay_url
        );
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

    println!("Waiting for sender to join room...");

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

    println!("Sender '{}' connected.", tx_payload.device_name);

    // Generate our X25519 ephemeral keypair
    let our_ephemeral = EphemeralKeyPair::generate();
    let our_nonce: [u8; 32] = rand::random();

    // Send our handshake back
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
    let handshake_bytes = serde_json::to_vec(&handshake_out)?;
    let signal_data = encrypt_signal(&phrase_seed, &handshake_bytes)?;
    let sig_req = WsSignal {
        r#type: "signal",
        room_id: room_id.clone(),
        data: signal_data,
    };
    let sig_json = serde_json::to_string(&sig_req)?;
    ws_write.send(Message::Text(sig_json.into())).await?;
    // Sleep to ensure the relay receives and forwards the signal before we close the WebSocket connection
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Perform DH key exchange
    let tx_ephemeral_pub = x25519_dalek::PublicKey::from(tx_payload.ephemeral_public);
    let session_keys =
        our_ephemeral.derive_session_keys(&tx_ephemeral_pub, &our_nonce, &tx_payload.nonce);

    // Save peer info
    let mut updated_config = config.clone();
    if !updated_config
        .peers
        .iter()
        .any(|p| p.device_id == tx_payload.device_id)
    {
        updated_config.peers.push(crate::storage::PeerInfo {
            name: tx_payload.device_name.clone(),
            device_id: tx_payload.device_id,
        });
        let _ = crate::storage::save_config(&updated_config);
    }

    println!("Receiver: Connecting to sender over Iroh P2P...");
    let conn = endpoint.connect(tx_payload.node_addr, b"arc/1").await?;
    println!("Receiver: QUIC connection established over Iroh.");

    let clipboard_res = run_quic_receiver_session(
        &conn,
        output_dir,
        &session_keys,
        tx_payload.device_id,
        progress_tx.clone(),
        stdout_tx.clone(),
        &tx_payload.device_name,
    )
    .await?;

    Ok(clipboard_res)
}
