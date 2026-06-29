//! arc-relay: WebSocket signaling relay for arc.
//!
//! Responsibilities:
//! - Accept WebSocket connections from arc clients
//! - Route signaling messages between two-party rooms
//! - Enforce the 2-member room limit (INV-9)
//! - Rate limit room creation per IP
//! - Report room member counts for MITM detection
//!
//! The relay is intentionally zero-knowledge:
//! - It sees opaque ciphertext, never plaintext file content
//! - Room IDs are SHA256(nonce) — the relay cannot infer the pairing nonce
//! - All payload is encrypted by arc-core before reaching the relay

use axum::{
    Router,
    extract::{
        ConnectInfo, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
    routing::get,
};
use clap::Parser;
use dashmap::DashMap;
use prometheus::{IntCounter, IntGauge, Registry};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::sync::broadcast;
use tracing::{info, warn};
use uuid::Uuid;

// ─── Configuration ────────────────────────────────────────────────────────────

const MAX_MEMBERS_PER_ROOM: usize = 2;

// ─── Metrics ──────────────────────────────────────────────────────────────────

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(Registry::new)
}

fn active_rooms() -> &'static IntGauge {
    static ACTIVE_ROOMS: OnceLock<IntGauge> = OnceLock::new();
    ACTIVE_ROOMS.get_or_init(|| {
        let gauge =
            IntGauge::new("arc_relay_active_rooms", "Number of currently active rooms").unwrap();
        registry().register(Box::new(gauge.clone())).unwrap();
        gauge
    })
}

fn active_connections() -> &'static IntGauge {
    static ACTIVE_CONNECTIONS: OnceLock<IntGauge> = OnceLock::new();
    ACTIVE_CONNECTIONS.get_or_init(|| {
        let gauge = IntGauge::new(
            "arc_relay_active_connections",
            "Number of currently active WebSocket connections",
        )
        .unwrap();
        registry().register(Box::new(gauge.clone())).unwrap();
        gauge
    })
}

fn bytes_relayed() -> &'static IntCounter {
    static BYTES_RELAYED_CELL: OnceLock<IntCounter> = OnceLock::new();
    BYTES_RELAYED_CELL.get_or_init(|| {
        let counter = IntCounter::new(
            "arc_relay_bytes_relayed_total",
            "Total bytes relayed through the server",
        )
        .unwrap();
        registry().register(Box::new(counter.clone())).unwrap();
        counter
    })
}

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

struct TokenBucket {
    tokens: f64,
    last_update: Instant,
}

impl TokenBucket {
    fn new(max_tokens: f64) -> Self {
        Self {
            tokens: max_tokens,
            last_update: Instant::now(),
        }
    }

    fn check_and_consume(&mut self, max_tokens: f64, refill_rate: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;
        self.tokens = (self.tokens + elapsed * refill_rate).min(max_tokens);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ─── State ────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BroadcastPayload {
    sender_id: String,
    payload: String,
}

#[derive(Clone)]
struct RelayRoom {
    member_count: u8,
    max_members: usize,
    created_at: Instant,
    tx: broadcast::Sender<BroadcastPayload>,
}

#[derive(Clone)]
struct AppState {
    rooms: Arc<DashMap<String, RelayRoom>>,
    rate_limiter: Arc<DashMap<IpAddr, Mutex<TokenBucket>>>,
    max_rooms: usize,
    room_ttl_secs: u64,
}

impl AppState {
    fn new(max_rooms: usize, room_ttl_secs: u64) -> Self {
        Self {
            rooms: Arc::new(DashMap::new()),
            rate_limiter: Arc::new(DashMap::new()),
            max_rooms,
            room_ttl_secs,
        }
    }
}

// ─── Wire Messages ────────────────────────────────────────────────────────────

/// Messages sent by clients to the relay.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    /// Join or create a room.
    Join {
        room_id: String,
        #[allow(dead_code)]
        max_members: Option<usize>,
    },
    /// Forward a signaling payload to the peer in the same room.
    Signal { room_id: String, data: String },
    /// Leave the room gracefully.
    Leave { room_id: String },
}

/// Messages sent by the relay to clients.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RelayMessage {
    /// Acknowledged room join.
    Joined { room_id: String, member_count: u8 },
    /// Current room member count (clients use this for INV-9 check).
    RoomMemberCount { room_id: String, count: u8 },
    /// A signal payload forwarded from the other room member.
    Signal { data: String },
    /// Error message.
    Error { message: String },
}

// ─── CLI Arguments ────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "arc-relay", version, about = "Relay server for arc")]
struct Args {
    /// Address to bind to
    #[arg(long, default_value = "0.0.0.0", env = "ARC_RELAY_BIND")]
    bind: String,

    /// Port to listen on
    #[arg(long, default_value = "9000", env = "ARC_RELAY_PORT")]
    port: u16,

    /// Room time-to-live in seconds
    #[arg(long, default_value = "600", env = "ARC_RELAY_ROOM_TTL")]
    room_ttl: u64,

    /// Maximum total rooms allowed
    #[arg(long, default_value = "10000", env = "ARC_RELAY_MAX_ROOMS")]
    max_rooms: usize,

    /// Path to TLS certificate PEM file
    #[arg(long, env = "ARC_RELAY_TLS_CERT")]
    tls_cert: Option<String>,

    /// Path to TLS private key PEM file
    #[arg(long, env = "ARC_RELAY_TLS_KEY")]
    tls_key: Option<String>,
}

// ─── Handlers ────────────────────────────────────────────────────────────────

async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let ip = addr.ip();
    let mut allowed = true;
    {
        let entry = state
            .rate_limiter
            .entry(ip)
            .or_insert_with(|| Mutex::new(TokenBucket::new(5.0)));
        if let Ok(mut bucket) = entry.lock() {
            // 5 max tokens, refills 0.1/sec (1 every 10 seconds)
            if !bucket.check_and_consume(5.0, 0.1) {
                allowed = false;
            }
        } else {
            allowed = false;
        }
    }

    if !allowed {
        warn!(ip = ?ip, "rate limit exceeded for connection");
        return axum::http::StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    // Limit WebSocket message size to 1 MB
    ws.max_message_size(1024 * 1024)
        .on_upgrade(move |socket| handle_socket(socket, state, client_id_str()))
}

fn client_id_str() -> String {
    Uuid::new_v4().to_string()
}

async fn handle_socket(mut socket: WebSocket, state: AppState, client_id: String) {
    info!(client_id = %client_id, "client connected");
    active_connections().inc();

    let mut current_room: Option<String> = None;
    let mut room_rx: Option<broadcast::Receiver<BroadcastPayload>> = None;

    // SEC-11: Per-connection message rate limit (20 tokens, refills 5/sec)
    let mut msg_limiter = TokenBucket::new(20.0);

    loop {
        tokio::select! {
            // Receive message from client
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if !msg_limiter.check_and_consume(20.0, 5.0) {
                            warn!(client_id = %client_id, "per-connection message rate limit exceeded");
                            let err = RelayMessage::Error { message: "rate limit exceeded".to_string() };
                            if let Ok(err_json) = serde_json::to_string(&err) {
                                let _ = socket.send(Message::Text(err_json.into())).await;
                            }
                            break;
                        }

                        match serde_json::from_str::<ClientMessage>(&text) {
                            Ok(ClientMessage::Join { room_id, .. }) => {
                                // BUG-6: Leave old room before joining a new one
                                if let Some(old_room) = current_room.take() {
                                    handle_leave(&state, old_room, &client_id).await;
                                }
                                handle_join(&mut socket, &state, &mut current_room, &mut room_rx, room_id, &client_id).await;
                            }
                            Ok(ClientMessage::Signal { room_id, data }) => {
                                handle_signal(&state, room_id, data, &client_id).await;
                            }
                            Ok(ClientMessage::Leave { room_id }) => {
                                handle_leave(&state, room_id, &client_id).await;
                                break;
                            }
                            Err(e) => {
                                let err = RelayMessage::Error { message: format!("invalid message: {e}") };
                                if let Ok(err_json) = serde_json::to_string(&err) {
                                    let _ = socket.send(Message::Text(err_json.into())).await;
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        if let Some(room_id) = &current_room {
                            handle_leave(&state, room_id.clone(), &client_id).await;
                        }
                        break;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        warn!(client_id = %client_id, error = %e, "WebSocket error");
                        if let Some(room_id) = &current_room {
                            handle_leave(&state, room_id.clone(), &client_id).await;
                        }
                        break;
                    }
                }
            }
            // Forward broadcast messages from room peers, filtering out self-signals
            Some(peer_msg) = async {
                if let Some(rx) = &mut room_rx {
                    rx.recv().await.ok()
                } else {
                    None
                }
            } => {
                if peer_msg.sender_id != client_id {
                    let msg_json = if peer_msg.sender_id == "relay" {
                        peer_msg.payload
                    } else {
                        let relay_msg = RelayMessage::Signal { data: peer_msg.payload };
                        serde_json::to_string(&relay_msg).unwrap_or_default()
                    };
                    if !msg_json.is_empty() {
                        let _ = socket.send(Message::Text(msg_json.into())).await;
                    }
                }
            }
        }
    }

    active_connections().dec();
    info!(client_id = %client_id, "client disconnected");
}

async fn handle_join(
    socket: &mut WebSocket,
    state: &AppState,
    current_room: &mut Option<String>,
    room_rx: &mut Option<broadcast::Receiver<BroadcastPayload>>,
    room_id: String,
    client_id: &str,
) {
    if room_id.len() != 64 || !room_id.chars().all(|c| c.is_ascii_hexdigit()) {
        let err = RelayMessage::Error {
            message: "room_id must be 64-char hex (SHA256)".to_string(),
        };
        if let Ok(err_json) = serde_json::to_string(&err) {
            let _ = socket.send(Message::Text(err_json.into())).await;
        }
        return;
    }

    if state.rooms.len() >= state.max_rooms {
        let err = RelayMessage::Error {
            message: "relay at capacity".to_string(),
        };
        if let Ok(err_json) = serde_json::to_string(&err) {
            let _ = socket.send(Message::Text(err_json.into())).await;
        }
        return;
    }

    let (member_count, rx) = {
        let mut entry = state.rooms.entry(room_id.clone()).or_insert_with(|| {
            let (tx, _) = broadcast::channel(32);
            RelayRoom {
                member_count: 0,
                max_members: MAX_MEMBERS_PER_ROOM, // Enforce server-side limit of 2 (INV-9)
                created_at: Instant::now(),
                tx,
            }
        });

        if entry.member_count as usize >= entry.max_members {
            let err = RelayMessage::Error {
                message: format!("room is full (max {} members)", entry.max_members),
            };
            drop(entry);
            if let Ok(err_json) = serde_json::to_string(&err) {
                let _ = socket.send(Message::Text(err_json.into())).await;
            }
            return;
        }

        entry.member_count += 1;
        let count = entry.member_count;
        let rx = entry.tx.subscribe();
        (count, rx)
    };

    info!(client_id = %client_id, room_id = %&room_id[..8], member_count, "joined room");
    active_rooms().set(state.rooms.len() as i64);

    *current_room = Some(room_id.clone());
    *room_rx = Some(rx);

    let joined = RelayMessage::Joined {
        room_id: room_id.clone(),
        member_count,
    };
    if let Ok(joined_json) = serde_json::to_string(&joined) {
        let _ = socket.send(Message::Text(joined_json.into())).await;
    }

    let count_msg = RelayMessage::RoomMemberCount {
        room_id: room_id.clone(),
        count: member_count,
    };
    if let (Some(room), Ok(count_json)) =
        (state.rooms.get(&room_id), serde_json::to_string(&count_msg))
    {
        let _ = room.tx.send(BroadcastPayload {
            sender_id: "relay".to_string(),
            payload: count_json,
        });
    }
}

async fn handle_signal(state: &AppState, room_id: String, data: String, client_id: &str) {
    if let Some(room) = state.rooms.get(&room_id) {
        bytes_relayed().inc_by(data.len() as u64);
        let _ = room.tx.send(BroadcastPayload {
            sender_id: client_id.to_string(),
            payload: data,
        });
    } else {
        warn!(client_id = %client_id, "signal to nonexistent room");
    }
}

async fn handle_leave(state: &AppState, room_id: String, client_id: &str) {
    let mut remove_room = false;
    if let Some(mut room) = state.rooms.get_mut(&room_id) {
        room.member_count = room.member_count.saturating_sub(1);
        info!(client_id = %client_id, room_id = %&room_id[..8.min(room_id.len())], "left room");
        if room.member_count == 0 {
            remove_room = true;
        }
    }
    if remove_room {
        state
            .rooms
            .remove_if(&room_id, |_, room| room.member_count == 0);
    }
    active_rooms().set(state.rooms.len() as i64);
}

async fn health() -> &'static str {
    "OK"
}

static METRICS_TOKEN: OnceLock<String> = OnceLock::new();

async fn metrics_handler(headers: axum::http::HeaderMap) -> impl IntoResponse {
    let expected_token = METRICS_TOKEN
        .get()
        .map(|s| s.as_str())
        .unwrap_or("disabled_default_token");
    let authenticated = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .map(|s| s == format!("Bearer {}", expected_token))
        .unwrap_or(false);
    if authenticated {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = registry().gather();
        let mut buffer = Vec::new();
        if encoder.encode(&metric_families, &mut buffer).is_ok() {
            return axum::response::Response::builder()
                .header("content-type", encoder.format_type())
                .body(axum::body::Body::from(buffer))
                .unwrap_or_default()
                .into_response();
        }
    }
    axum::http::StatusCode::UNAUTHORIZED.into_response()
}

// Helper for graceful shutdown
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "arc_relay=info".into()),
        )
        .init();

    let args = Args::parse();
    let state = AppState::new(args.max_rooms, args.room_ttl);

    let token = std::env::var("ARC_RELAY_METRICS_TOKEN").unwrap_or_else(|_| {
        let rand_token = Uuid::new_v4().to_string();
        info!(
            "ARC_RELAY_METRICS_TOKEN env var not set. Generated a random secure token: {}",
            rand_token
        );
        rand_token
    });
    let _ = METRICS_TOKEN.set(token);

    // Background task: expire rooms older than room_ttl_secs and notify clients
    {
        let state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let cutoff = Instant::now() - Duration::from_secs(state.room_ttl_secs);
                state.rooms.retain(|room_id, room| {
                    let expired = room.created_at < cutoff;
                    if expired {
                        warn!(room_id = %&room_id[..8.min(room_id.len())], "room expired (TTL)");
                        let expiry_msg = RelayMessage::Error {
                            message: "room expired".to_string(),
                        };
                        if let Ok(payload_str) = serde_json::to_string(&expiry_msg) {
                            let _ = room.tx.send(BroadcastPayload {
                                sender_id: "relay".to_string(),
                                payload: payload_str,
                            });
                        }
                    }
                    !expired
                });
                active_rooms().set(state.rooms.len() as i64);
            }
        });
    }

    // SEC-10: Background task: clean up rate limiter entries older than 3600 seconds
    {
        let rate_limiter = state.rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(600));
            loop {
                interval.tick().await;
                let cutoff = Instant::now() - Duration::from_secs(3600);
                rate_limiter.retain(|_, bucket_mutex| {
                    if let Ok(bucket) = bucket_mutex.get_mut() {
                        bucket.last_update >= cutoff
                    } else {
                        true
                    }
                });
            }
        });
    }

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/health", get(health))
        .route("/metrics", get(metrics_handler))
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", args.bind, args.port).parse()?;
    info!(addr = %addr, "arc-relay starting");

    if let (Some(cert_path), Some(key_path)) = (args.tls_cert, args.tls_key) {
        info!("Starting relay in TLS mode");
        let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            PathBuf::from(cert_path),
            PathBuf::from(key_path),
        )
        .await?;

        let handle = axum_server::Handle::new();
        let handle_clone = handle.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            info!("Received shutdown signal, starting graceful drain under TLS mode...");
            handle_clone.graceful_shutdown(Some(Duration::from_secs(10)));
        });

        axum_server::bind_rustls(addr, config)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        info!("Starting relay in plain HTTP/WS mode");
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    }

    Ok(())
}
