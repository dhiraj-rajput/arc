# `arc` — Improved Master Engineering Plan
## Deep Competitive Analysis + Research-Backed Upgrades

---

# PART 0: COMPETITIVE ANALYSIS — HOW ARC COMPARES TO CROC AND THE FIELD

## croc (schollz) — Deep Teardown

**What croc is:** A CLI Go tool (~35K GitHub stars) for one-shot, PAKE-authenticated file
transfer via a TCP relay. The code phrase (3–5 English words) is used to establish a shared
session key through Password-Authenticated Key Exchange; AES-256 encrypts content. A relay
"staples" two TCP connections together and pipes bytes transparently. There is no persistent
device pairing; every transfer starts fresh.

### croc's Transport Architecture (its biggest weakness)

```
croc Architecture (v10.x):
  Sender TCP:9009  ──► Relay (staple) ◄──  Receiver TCP:9009
  Sender TCP:9010  ──► Relay (staple) ◄──  Receiver TCP:9010
  Sender TCP:9011  ──► ...
  
  LAN discovery: UDP multicast (same subnet only)
  No UDP hole-punch, no QUIC, no connection migration
```

croc requires **5 open TCP ports (9009–9013)**, which are blocked in many corporate
environments. It has no QUIC, no NAT traversal beyond the relay, and no parallel stream
multiplexing — a single connection per session.

### croc's Documented Security Vulnerabilities (all CVE-level)

Six security advisories were filed against croc v9 in 2023, showing the pitfalls of
ad-hoc protocol design that arc must avoid by design:

| Advisory | Vulnerability | Root Cause | Arc's Defense |
|---|---|---|---|
| GO-2023-2068 | ANSI/CSI escape sequences in filename → terminal control injection | Filename printed raw to terminal | All filenames sanitized + stripped of control chars before display |
| GO-2023-2069 | Shared secret exposed to local users via process name | Secret passed as CLI argument visible in `ps aux` | Arc uses OS keystore + Unix socket IPC; no secrets in argv |
| GO-2023-2070 | Local IP addresses sent in cleartext to relay | IP addresses unencrypted in signaling | Arc relay signaling uses opaque base64 blobs; relay never sees IPs |
| GO-2023-2071 | Zip path traversal → receiver file overwrite | `../` not blocked in zip filenames | Arc validates all path components; blocks `..` traversal globally |
| GO-2023-2072 | Custom shared secret partially disclosed to untrusted relay | Secret was used directly as part of room name | Arc room ID = SHA256(nonce); relay never sees nonce, only its hash |
| GO-2023-2073 | Sender can inject dangerous new files to receiver mid-transfer | File list mutable during session | Arc's TransferOffer is immutable after acceptance; new files need new offer |

### Where Arc Beats croc in Every Dimension

```
Dimension               │ croc v10          │ arc (planned)
────────────────────────┼───────────────────┼──────────────────────────────
Transport               │ TCP only          │ QUIC > TCP > WebSocket cascade
NAT traversal           │ Relay only        │ Hole punch first, relay fallback
LAN fast path           │ UDP multicast     │ mDNS + direct QUIC
Encryption              │ AES-256 (PAKE)    │ ChaCha20-Poly1305 (device key)
Key exchange            │ PAKE per transfer │ Ed25519 device identity + X25519
Pairing model           │ None (code/xfer)  │ Persistent trusted devices
Forward secrecy         │ Partial           │ Full (ephemeral X25519 per session)
Mobile app              │ None (3rd party)  │ Flutter + flutter_rust_bridge FFI
Clipboard sync          │ Basic (v10.1)     │ Full daemon sync, loop-safe
Resume on disconnect    │ Yes               │ Yes (disk-persisted bitmap)
Daemon mode             │ No                │ Yes (systemd/launchd/registry)
Protocol port req.      │ 5 TCP ports       │ 443 (WSS) only in worst case
Congestion control      │ OS TCP default    │ BBRv3 configurable
Post-quantum ready      │ No                │ Hybrid X25519+ML-KEM roadmap
Terminal injection safe │ No (fixed in v9.6)│ Yes (by design, not by patch)
Secret leak to relay    │ Fixed in v9.6.6   │ Impossible by design
```

---

## iroh 1.0 (n0-computer) — The State of the Art in Rust QUIC P2P

Released **June 15, 2026**, iroh 1.0 is the most advanced open-source QUIC P2P library
in Rust and the single most important project to study for arc's transport layer.

### What iroh achieves (production numbers from n0's relay fleet):
- **95% of data volume** passes over direct peer-to-peer connections (relay is fallback only)
- **~90% NAT hole-punch success rate** (vs croc's 0% — it always relays)
- **EndpointId = Ed25519 public key** (not IP:port) — stable across network changes
- **Connection migration** built-in via QUIC; WiFi→cellular switch is seamless
- **Relay servers are stateless** and see only encrypted packets addressed to EndpointIds
- Ships official bindings for **Rust, Python, Node.js, Swift, and Kotlin** (1.0 guarantee)

### iroh-blobs: BLAKE3 Verified Streaming

iroh-blobs is the file-transfer protocol layer that arc should deeply study:
- Content-addressed by BLAKE3 hash — the hash IS the file's identity
- **Verified streaming**: receiver verifies each chunk against a BLAKE3 Merkle tree
  *as it arrives*, not after full assembly. This means a 10GB file can be verified in flight.
- HashSeq: a blob that contains a sequence of links → efficient directory transfers
- Resumable by design: re-request only missing chunks by BLAKE3 hash

**Key insight arc should adopt**: BLAKE3 Merkle tree hashing enables *partial verification*
during streaming, not just at the end. Arc's current design hashes each chunk independently
and also the whole file. It should upgrade to a Merkle tree model where the root hash
in TransferOffer commits to the entire tree, enabling single-pass O(log n) verification.

### Where arc deliberately differs from iroh

iroh is a **transport library**, not an end-user tool. It has:
- No CLI for end users
- No clipboard sync
- No mobile app
- No daemon mode
- No human-readable pairing codes
- No progress display

Arc fills the entire user-facing stack iroh deliberately leaves empty. The right architecture:

```
arc = iroh-style transport + user-facing features on top
```

Strongly consider: Replace arc's custom quinn + STUN + hole-punch code with **iroh as the
transport layer**. This gives arc iroh's 90%+ hole-punch success rate for free, keeps the
relay compatible, and reduces transport surface area from ~3000 lines to ~300 lines.
The EndpointId model (public key as address) maps exactly to arc's device identity.

---

## magic-wormhole — Security Gold Standard

magic-wormhole (Python/Rust/Go implementations) is the original PAKE file transfer tool.
Key architectural differences from croc and arc:

- Uses **SPAKE2** (not croc's siec curve PAKE) — better cryptographic pedigree
- Each code is **single-use** — one wrong guess notifies both parties of the interception
- Mailbox server (relay) forwards PAKE messages only; actual transfer is peer-to-peer
- The Dilation protocol uses Noise_NNpsk0 (ChaCha20-Poly1305 + BLAKE2s) for P2P data

**What arc learns from magic-wormhole**: The one-use code model and the explicit MITM
notification ("crowded" / "scary" error when a relay detects a third party). Arc should
implement the same: if a room has more than 2 members, abort and warn both parties.

---

## LocalSend — Flutter/Rust Hybrid to Learn From

LocalSend (79K GitHub stars as of 2026) is the dominant cross-platform LAN file transfer
tool and the main competitor in the local-network segment:
- Flutter UI + **Rust HTTP server/client** via `rhttp` + `flutter_rust_bridge`
- REST over HTTPS (not QUIC) — simple, reliable, firewall-friendly on port 53317
- No WAN capability, no relay, no NAT traversal — LAN only
- No pairing — broadcasts device name/cert on local network
- **40 MB/s** achieved in practice on local WiFi

LocalSend's lesson for arc: The Rust-for-I/O, Flutter-for-UI model works in production
at scale. Arc's flutter_rust_bridge design mirrors exactly what LocalSend ships.
LocalSend's weakness (LAN-only) is arc's primary advantage.

---

## sendme (n0-computer) — Simplest iroh-blobs CLI

sendme is a minimal Rust CLI built on iroh-blobs: `sendme send <file>` produces a ticket;
`sendme receive <ticket>` fetches it. Location-transparent (ticket stays valid if IP changes).
Connections fall back to relay if direct connection fails. BLAKE3 verified streaming.

**sendme's weakness vs arc**: No pairing, no clipboard, no daemon, no human codes —
just raw iroh tickets (long base64 strings). Arc's UX is dramatically friendlier.

---

# PART 1: UPGRADED PROJECT VISION

## What arc is (revised)

A **universal, end-to-end encrypted, peer-to-peer file and clipboard transfer tool**
for any two devices (laptop ↔ laptop, laptop ↔ phone), with:

1. **Better security than croc** — device-based persistent trust, not per-transfer codes
2. **Better transport than croc** — QUIC first, 90%+ direct connections like iroh
3. **Better UX than iroh/sendme** — human codes, daemon, clipboard sync, mobile app
4. **Better WAN capability than LocalSend** — works across the internet, not just LAN
5. **Post-quantum roadmap** — ML-KEM hybrid key exchange planned for v2

---

# PART 2: UPGRADED PROTOCOL DESIGN

## 2.1 Consider iroh as Transport Layer (Strongly Recommended)

Instead of building quinn + STUN + hole-punch from scratch, arc can use iroh as its
transport layer. This means:

```toml
[dependencies]
iroh = "1.0"               # QUIC P2P: NAT traversal, relay, connection migration
iroh-blobs = "0.35"        # BLAKE3 verified streaming (optional but recommended)
```

The EndpointId maps 1:1 to arc's device_id:
```rust
use iroh::Endpoint;
// Each device's iroh Endpoint has an Ed25519 SecretKey whose public key is its identity.
// This IS arc's device_id. No separate arc identity layer needed.
let endpoint = Endpoint::bind(presets::N0).await?;
let device_id = endpoint.node_id(); // = Ed25519 public key
```

**Risk**: iroh 1.0 just shipped; API stability is now guaranteed, but ecosystem is new.
**Mitigation**: Arc's `arc-core/src/transport/` abstraction layer means iroh can be swapped
in/out without changing the rest of the codebase. Build the abstraction first, iroh second.

## 2.2 BLAKE3 Verified Streaming (Upgrade from chunk hashing)

Current arc plan: hash each chunk independently. Upgrade to Merkle tree model:

```
File data split into 1 KiB leaf chunks (BLAKE3's native chunk size)
└─ BLAKE3 Merkle tree built over leaves
   └─ Root hash = the file's permanent identity
      └─ Included in TransferOffer.file_hash (unchanged wire format)

Streaming verification:
  Each 1 KiB leaf: verified against its Merkle proof (O(log n) bytes)
  Receiver can verify WITHOUT assembling the full file first
  Out-of-order delivery: still works — each chunk verifiable independently
  
Resume: receiver already has BLAKE3 root; re-request specific leaf ranges
```

The BLAKE3 crate's `Hasher` supports this natively:
```rust
use blake3::Hasher;
// Parallel hashing of large files: BLAKE3 uses SIMD + multi-thread automatically
let hash = blake3::hash(&data); // single-threaded
// For large files: use rayon feature for parallel hashing
```

BLAKE3 on an 8-core machine hashes a 25 GB file in ~1.5 seconds vs SHA-256's 25-30 seconds.
The rayon feature in the blake3 crate enables full parallel utilization automatically.

## 2.3 Protocol Message Upgrades

### Add to ArcMessage enum:
```rust
// Missing from original plan — add these:

// Relay room integrity check (prevents relay substitution attack)
RoomIntegrity { room_members: u8 },  // relay reports member count; >2 = abort

// File deduplication (inspired by croc's imohash, upgraded)
TransferOfferWithDedup {
    transfer_id: Uuid,
    kind: TransferKind,
    file_name: String,
    total_size: u64,
    chunk_count: u32,
    chunk_size: u32,
    file_hash: [u8; 32],       // BLAKE3 root
    partial_hash: [u8; 32],    // BLAKE3 of first+last 128KB (fast dedup probe)
},

// Transfer speed negotiation
TransferCapability {
    max_parallel_streams: u16,
    preferred_chunk_size_kb: u32,
    supports_compression: bool,
    supports_delta_transfer: bool,
},

// Explicit file metadata (not just name)
FileMetadata {
    transfer_id: Uuid,
    created_at: u64,     // unix timestamp
    modified_at: u64,    // unix timestamp  
    unix_permissions: Option<u32>,
    is_executable: bool,
    xattrs: Vec<(String, Vec<u8>)>,  // extended attributes (macOS spotlight, etc.)
},

// Compression support (new)
CompressedChunk {
    transfer_id: Uuid,
    index: u32,
    algorithm: CompressionAlgo,
    compressed_data: Bytes,
    original_size: u32,
    hash: [u8; 32],     // BLAKE3 of ORIGINAL (uncompressed) chunk
},

pub enum CompressionAlgo {
    None,
    Zstd,     // Zstandard: best ratio/speed tradeoff, Facebook-backed
    Lz4,      // LZ4: max speed, lower ratio (good for already-compressed files)
}
```

### Adaptive Compression Strategy (New — croc doesn't have this):
```
Before transfer, arc samples first 64KB of file and probes compressibility:
  If zstd level 1 ratio < 1.05 → file already compressed (JPEG, MP4, ZIP, etc.)
     → send uncompressed (avoid wasted CPU)
  If ratio > 1.3 → significant gain (text, logs, code, JSON)
     → compress with zstd level 3 (fast, ~5 GB/s on modern CPU)
  If ratio 1.05–1.3 → marginal → try lz4 (fastest, ~10 GB/s)

This alone yields 3–10× speedup for text/code transfers.
```

## 2.4 Protocol Versioning (Upgrade)

Current plan uses a single u16 version. Upgrade to capability negotiation:

```rust
// Hello message upgrade
Hello {
    protocol_version: u16,      // wire format version
    capabilities: CapabilityFlags,
    device_id: [u8; 32],
    nonce: [u8; 32],
}

bitflags! {
    pub struct CapabilityFlags: u32 {
        const QUIC_MULTIPATH     = 0x0001;  // supports multipath QUIC
        const COMPRESSION_ZSTD   = 0x0002;  // zstd compression
        const COMPRESSION_LZ4    = 0x0004;  // lz4 compression
        const BLAKE3_VERIFIED_STREAMING = 0x0008; // Merkle tree streaming verify
        const DELTA_TRANSFER     = 0x0010;  // rsync-style delta (v2)
        const POST_QUANTUM_HYBRID = 0x0020; // ML-KEM-768 hybrid key exchange
        const MULTICAST_RECEIVE  = 0x0040;  // can receive from multiple senders
    }
}
```

---

# PART 3: UPGRADED SECURITY MODEL

## 3.1 Croc's Lessons Applied to Arc by Design

Every croc vulnerability has a structural fix in arc. The table in Part 0 covers this.
The three most important:

**Filename display safety** (GO-2023-2068): Never print raw filenames to terminal.
Always pass through the sanitizer BEFORE any display, even in progress bars:
```rust
fn safe_display_name(raw: &str) -> String {
    raw.chars()
       .map(|c| if c.is_control() || c == '\x1b' { '?' } else { c })
       .take(255)
       .collect()
}
```

**Secret-in-room-name** (GO-2023-2072): Arc's room ID = SHA256(pairing_nonce).
The nonce never leaves the sender/receiver. The relay only ever sees the hash.
This is correct as specified in arc v1 plan. Verify this is maintained when
implementing — easy to accidentally leak by using nonce directly.

**Process-name leak** (GO-2023-2069): Arc daemon uses Unix socket IPC, not CLI args,
for passing secrets. The secret is never in argv. Verify with:
```bash
# Should show no secret in any arc process args:
ps aux | grep arc | grep -v grep
```

## 3.2 Zero-Knowledge Relay Design

Upgrade arc-relay to be genuinely zero-knowledge — the relay operator learns nothing
about who is communicating with whom:

```
Current design: Room ID = SHA256(nonce) — relay knows room ID
Upgrade:        Room ID = SHA256(nonce) — unchanged (relay still knows this)
                BUT: all signaling messages are also encrypted with pairing_key
                  { "type": "signal", "data": base64(encrypt(pairing_key, payload)) }
                  
This means relay cannot correlate room usage patterns even if it logs everything.
The relay only knows: "two connections joined room X, then left."
It cannot see pairing codes, device IDs, file metadata, or IP addresses of peers.
```

## 3.3 Room Integrity Check (New — Prevents Active Relay Attack)

Inspired by magic-wormhole's "crowded" / "scary" error:

```rust
// In relay → client signaling:
{ "type": "room_member_count", "count": 3 }  // relay sends honest count

// In arc-core: if room has more than 2 members → abort immediately
if room_member_count > 2 {
    send(TransferAbort { reason: "relay_tampered".into() });
    warn_user("⚠️  Relay reported 3+ members in a 2-party room. Possible MITM. Aborting.");
    return Err(ArcError::RelayCompromised);
}
```

A compromised relay trying to inject itself as a third party will trigger this check.
This is the same security guarantee magic-wormhole provides.

## 3.4 Post-Quantum Cryptography Roadmap

**NIST finalized** FIPS 203 (ML-KEM / Kyber) and FIPS 204 (ML-DSA / Dilithium) in
August 2024. These are now production-ready standards.

**v1 plan (current)**: X25519 ephemeral + Ed25519 identity — classically secure.
**v2 plan**: Hybrid X25519+ML-KEM-768 key exchange.

The hybrid approach is used by Chrome (since 2023), AWS, Cloudflare, and Apple iMessage
(since February 2024). It provides quantum safety while maintaining classical security
if ML-KEM has unforeseen weaknesses.

Design now for PQC compatibility:
```rust
// The HKDF input structure should accommodate both:
// Classical:
HKDF(x25519_shared_secret, nonce, "arc-v1-session")

// Hybrid PQC (v2 upgrade, same HKDF call):
HKDF(x25519_shared_secret || ml_kem_shared_secret, nonce, "arc-v2-session")
// The || concatenation is intentional: breaks if either component is compromised
```

ML-KEM-768 adds ~1KB to the handshake (ciphertext size), which is negligible.
The hello message can carry the ML-KEM public key in an optional field, announced
via the `POST_QUANTUM_HYBRID` capability flag.

**Performance data (Intel i7-12700K, benchmarked 2025):**
- ML-KEM-768 key generation: < 0.1ms
- ML-KEM-768 encapsulation: < 0.1ms
- ML-KEM-768 decapsulation: < 0.1ms
- Total PQC overhead per handshake: < 1ms (vs ~5–50ms RTT)
- No meaningful performance cost.

## 3.5 Upgraded Key Hierarchy

```
Device Identity Key
  Classical:  Ed25519 (current plan — keep)
  PQC (v2):   ML-DSA-65 (Dilithium) for device signatures
  
Session Ephemeral Key Exchange
  Classical:  X25519 (current plan — keep)
  PQC (v2):   + ML-KEM-768 (Kyber) encapsulation
  
Session Key Derivation (HKDF upgrade):
  v1: HKDF(x25519_dh, nonce, "arc-v1-session")
  v2: HKDF(x25519_dh || ml_kem_ss, nonce, "arc-v2-session")
  
Symmetric Encryption: ChaCha20-Poly1305 (keep — quantum-resistant at 256-bit keys)
Hashing: BLAKE3 (keep — 128-bit quantum-resistance from Grover's, equivalent to SHA-256)
```

ChaCha20-Poly1305 with 256-bit keys already provides quantum resistance at the symmetric
layer. Only the key exchange (asymmetric) needs upgrading for post-quantum security.

---

# PART 4: UPGRADED TRANSPORT LAYER

## 4.1 BBRv3 Congestion Control (Critical Performance Upgrade)

Quinn's default congestion control is **NewReno** — designed for lossy wired networks.
For arc's use cases (4G LTE, WiFi, cross-continental WAN), BBRv3 is dramatically better:

| Network Condition | BBRv3 vs NewReno (Quinn default) |
|---|---|
| 4G LTE (20ms RTT) | +45% throughput, -30% latency |
| Wi-Fi (5ms RTT) | +20% throughput, -15% latency |
| Satellite (600ms RTT) | +120% throughput, -40% latency |
| Lossy network (5% loss) | +200% throughput, -60% latency |

Quinn (0.11) supports pluggable congestion control. Configure it:
```rust
use quinn::congestion::{BbrConfig, ControllerFactory};

let mut transport_config = TransportConfig::default();
transport_config.congestion_controller_factory(Arc::new(BbrConfig::default()));

// Also enable GSO (Generic Segmentation Offload) for bulk transfers:
transport_config.enable_segmentation_offload(true);
// GSO dramatically reduces CPU usage when sending many packets with same headers
```

Note: As of quinn 0.11, BBR support may be limited. Alternative: evaluate **TQUIC**
(Tencent's QUIC library in Rust) which natively supports BBRv3 and Multipath QUIC.
TQUIC provides APIs compatible with the same async Rust patterns quinn uses.

## 4.2 Consider iroh for Transport (Replaces Custom STUN + Hole Punch)

Building STUN + hole-punch + relay from scratch is the highest-risk part of arc's plan.
iroh 1.0 has spent 4+ years solving exactly this problem. Strong recommendation:

```
Option A: Use iroh as transport layer
  + 90%+ hole-punch success (production-proven)
  + Connection migration (WiFi→LTE) built-in
  + QUIC multipath support (added Feb 2026)
  + Zero maintenance burden on NAT traversal edge cases
  + BLAKE3 verified streaming via iroh-blobs
  - Dependency on n0's relay infrastructure (can self-host their relay code)
  - Another crate to pin and track

Option B: Custom quinn + STUN + hole-punch (original plan)
  + Full control
  + No dependency on external org's decisions
  - 6–8 weeks of complex, security-critical code
  - ~15% of internet (symmetric NAT) always falls back to relay anyway
  - Risk of the same vulnerabilities croc had
```

**Recommendation**: Use iroh for transport in arc-core, expose arc's existing abstraction
interface. The iroh EndpointId (Ed25519 public key) maps directly to arc's device_id.
This reduces transport implementation from weeks to days and gives production-proven
95% direct connection rates immediately.

## 4.3 Multipath QUIC (Future-Ready Design)

iroh added multipath QUIC in February 2026 (QUIC multipath RFC draft). This means:
- Simultaneous use of WiFi + cellular paths for a single connection
- Seamless failover without re-establishing the connection
- Higher aggregate throughput by bonding multiple interfaces

Design arc's transfer engine to be multipath-aware:
```rust
// Stream allocation hint for multipath:
// Even-numbered streams → path 0 (WiFi, typically faster)
// Odd-numbered streams  → path 1 (LTE, backup)
// This allows natural load balancing across paths
```

## 4.4 Transport Selection Algorithm (Upgraded)

```
arc send file.jpg
│
├─[1] Is peer on same LAN? (mDNS, 100ms timeout)
│      └─► YES: QUIC directly to peer's LAN IP          → FASTEST PATH (~1-5 GB/s)
│
├─[2] Try iroh hole punch (or custom STUN punch, 2s timeout)
│      ├─ Exchange EndpointIds via relay signaling
│      ├─ Attempt QUIC NAT traversal simultaneously
│      └─► SUCCESS: direct QUIC P2P (iroh-style)       → FAST PATH (~50-200 MB/s)
│
├─[3] Try TCP+TLS fallback (if UDP blocked everywhere)
│      └─► Both sides connect to relay TCP bridge       → MEDIUM PATH (~30-100 MB/s)
│
└─[4] WebSocket fallback (port 443 only, corporate firewall)
       └─► WSS to relay on port 443 + TLS               → SLOW PATH (always works)

Changes from original plan:
  - Add adaptive compression before transfer (saves bandwidth on text/code)
  - Add multipath detection: if two paths available, bond them
  - Race mDNS probe AND hole punch in parallel (not sequentially)
  - Timeout: 100ms for LAN probe (not 50ms — 50ms too aggressive for mDNS)
```

## 4.5 GSO / GRO for High-Throughput Scenarios

For high-bandwidth LAN transfers (target: saturate 10 GbE if available):

```rust
// Enable OS-level packet batching:
// GSO: Generic Segmentation Offload (Linux, Windows)
// GRO: Generic Receive Offload (Linux)
// These allow the OS to batch QUIC packets into large kernel writes,
// reducing syscall overhead from O(chunks) to O(1) per batch.

// In quinn-udp (the UDP layer quinn uses):
// GSO is automatically enabled when available, but must be explicitly
// not disabled in quinn's TransportConfig:
transport_config.enable_segmentation_offload(true); // default in quinn 0.11+
```

With GSO enabled on a modern Linux system, quinn achieves near-kernel-TCP throughput
for bulk file transfers. Without it, syscall overhead limits throughput to ~2–3 GB/s.

---

# PART 5: UPGRADED DISCOVERY AND NAT TRAVERSAL

## 5.1 Pkarr / BitTorrent DHT for Peer Discovery (Optional v2)

iroh uses BitTorrent's Mainline DHT as its global peer discovery mechanism. Each device
publishes a Pkarr record (signed packet with its current IP addresses) to the DHT.
This means two arc devices can find each other with only their EndpointId (public key),
even without a relay:

```rust
// Pkarr = Packet Key Addressing and Routing
// Publish arc device addresses to BitTorrent DHT:
// pkarr = { device_id: [ip4_addr, ip6_addr, relay_url] } signed with Ed25519 key
// Discovery: given a device_id, look up DHT → get current addresses
```

This eliminates dependency on arc's relay for discovery (relay still needed for relay
fallback, but not for finding peers). Plan for v2.

## 5.2 IPv6 Happy Eyeballs (Upgrade)

The current plan mentions IPv6 but doesn't specify implementation. Use RFC 8305
Happy Eyeballs v2:

```rust
// Attempt IPv6 and IPv4 in parallel with a 250ms head start for IPv6:
let ipv6_future = connect_quic(&peer_ipv6, port);
let ipv4_future = async {
    tokio::time::sleep(Duration::from_millis(250)).await; // IPv6 head start
    connect_quic(&peer_ipv4, port).await
};
let connection = tokio::select! {
    Ok(c) = ipv6_future => c,
    Ok(c) = ipv4_future => c,
};
```

IPv6 connections skip NAT entirely — if both devices have global IPv6, the fastest
path is direct IPv6 QUIC with no relay, no hole-punch. Always try this first.

## 5.3 NAT Type Detection (More Detail than Original Plan)

```
Detection method (improved — send STUN from two different local ports to two servers):

  STUN binding 1: Local:5000 → stun.cloudflare.com → External: X.X.X.X:Y
  STUN binding 2: Local:5001 → stun.l.google.com  → External: X.X.X.X:Z

  If Y == Z: Full cone or restricted cone → hole punch will work
  If Y != Z: Symmetric NAT               → hole punch will fail → skip to relay

Also test for hairpin NAT (devices behind same NAT connecting to each other):
  Both devices see same external IP → LAN path should work even for WAN-addressed transfers
```

---

# PART 6: UPGRADED FILE TRANSFER ENGINE

## 6.1 Fast Deduplication (Inspired by croc's imohash)

croc uses `imohash` — a fast approximate hash that samples the first and last
16KB of a file rather than hashing the whole thing. This enables fast "is this the
same file?" checks before committing to a full transfer. Arc should implement this:

```rust
/// Fast sampling hash for deduplication probing
/// Samples first + last 128KB + file size + metadata
pub fn arc_fast_hash(path: &Path) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let meta = fs::metadata(path)?;
    hasher.update(&meta.len().to_le_bytes());
    
    let mut file = File::open(path)?;
    // First 128KB
    let mut buf = vec![0u8; 131_072];
    let n = file.read(&mut buf)?;
    hasher.update(&buf[..n]);
    
    // Last 128KB (if file > 256KB)
    if meta.len() > 262_144 {
        file.seek(SeekFrom::End(-131_072))?;
        let n = file.read(&mut buf)?;
        hasher.update(&buf[..n]);
    }
    *hasher.finalize().as_bytes()
}
```

In TransferOffer, include both `file_hash` (full BLAKE3) and `partial_hash` (fast probe).
Receiver can check fast probe first — if no match, full transfer. If match, verify full hash
before accepting as deduplicated (partial hash is not cryptographic).

## 6.2 Delta Transfer (v2 design, prepare now)

For transfers to devices that have an older version of the same file (common in
laptop↔phone sync scenarios), rsync-style delta can reduce transfer volume by 90%+:

```
Protocol extension (v2):
  Sender: TransferOfferDelta { transfer_id, file_hash, block_size: 4096 }
  Receiver:
    - Compute rolling hash (Adler32) of each block in existing file
    - Send: DeltaBlockList { transfer_id, blocks: Vec<(u64, u32)> } // offset, adler32
  Sender:
    - Diff against receiver's blocks
    - Send only blocks that differ
    - Receiver: reconstructs file from diff + existing blocks

Design arc's chunking API with delta in mind:
  The Chunker trait should accept a "baseline_blocks" parameter (None for full transfer)
```

## 6.3 Upgraded Chunking Strategy

The original 1MB/4MB/8MB strategy is reasonable but can be improved:

```
File Size        │ Chunk Size │ Compression │ Why
─────────────────┼────────────┼─────────────┼──────────────────────────
< 64 KB          │ whole file │ Auto        │ No overhead at all
64 KB – 1 MB    │ 256 KB     │ Auto        │ Fast, low overhead
1 MB – 100 MB   │ 1 MB       │ Auto        │ Balance overhead/parallelism
100 MB – 1 GB   │ 4 MB       │ Auto        │ More throughput per stream  
> 1 GB           │ 8 MB       │ None*       │ Avoid double-buffering large chunks

*Large files are typically already compressed (video, archives).
 Compression probe at 64KB → skip if ratio < 1.05.
 
Parallel streams: min(64, ceil(total_chunks / 8))
  - Don't open 1000 streams for 1000 chunks — diminishing returns above ~64
  - 8 chunks per stream is a good balance of latency and parallelism
```

## 6.4 Memory-Mapped I/O for Large Files

For files > 100MB, use memory-mapped I/O to avoid buffering:

```rust
use memmap2::Mmap;

// Sender: map file read-only, slice into chunks by offset
let file = File::open(&path)?;
let mmap = unsafe { Mmap::map(&file)? };
// No Vec<u8> allocation — OS pages are mapped on demand
let chunk = &mmap[chunk_offset..chunk_offset + chunk_size];
// BLAKE3 and ChaCha20 can operate directly on the mmap slice

// Receiver: map temp file write-only, write by offset
let file = OpenOptions::new().write(true).create(true).open(&tmp_path)?;
file.set_len(total_size)?;
let mut mmap = unsafe { MmapMut::map_mut(&file)? };
mmap[chunk_offset..chunk_offset + chunk.len()].copy_from_slice(&chunk);
// OS handles ordering — no need for in-memory reassembly
mmap.flush()?;
```

This eliminates the "read file → buffer → encrypt → send" pipeline overhead and
allows the OS to use page cache efficiently. For 10GbE LAN transfers, this is the
difference between ~3 GB/s and ~8 GB/s throughput.

---

# PART 7: UPGRADED PAIRING AND KEY MANAGEMENT

## 7.1 QR Code Content Upgrade

Current plan: QR encodes the 6-word phrase. Upgrade to encode a full pairing ticket:

```
QR content (URL-safe base64 encoded):
  arc://pair?v=1&nonce=<hex>&relay=<base64_relay_url>&hint=<device_name>

Benefits:
  - Phone can pre-connect to relay before user confirms pairing
  - Includes relay hint → works without requiring user to configure relay
  - Device name hint → shows "Pair with MacBook Pro" on phone before scan completes
  - Backward compatible: unknown fields ignored by older clients
```

## 7.2 Trust-On-First-Use (TOFU) vs Fingerprint Verification

Arc's current plan requires fingerprint verification for every new pairing.
This is correct but should be configurable:

```toml
[security]
pairing_verification = "fingerprint"  # always require OOB fingerprint check
# pairing_verification = "tofu"       # trust first pairing without check (convenience)
# pairing_verification = "ssh"        # SSH-style: warn on key change only
```

The default must remain `fingerprint` for security. But `tofu` mode enables
AirDrop-style convenience for users who accept the risk.

## 7.3 Device Revocation

Missing from original plan:

```rust
// New CLI command
arc peers revoke "iPhone 15 Pro"
// Effect:
// 1. Removes pairing key from local keystore
// 2. Sends revocation signal to peer via relay (if online)
// 3. Peer removes our key from their keystore on receiving signal
// 4. Future connection attempts fail at AuthChallenge step

// Revocation format:
RevocationToken {
    device_id: [u8; 32],           // who is being revoked (us)
    timestamp: u64,                // when
    signature: [u8; 64],           // signed by our Ed25519 identity key
}
// Stored in peers.db: revoked_at TIMESTAMP (NULL = not revoked)
```

## 7.4 Emergency Kill Switch

For situations where a device is stolen:

```bash
arc panic
# Deletes: all pairing keys, all pending transfers, device identity key
# Generates: new device identity key
# Effect: all paired devices can no longer connect to this device
# Use case: stolen laptop
```

---

# PART 8: UPGRADED RELAY SERVER

## 8.1 Relay as True Packet Forwarder (iroh Model)

The original relay design forwards signaling and then proxies bytes. Upgrade to the
iroh relay model where the relay is completely content-blind:

```
Original design: relay understands arc signaling messages (join, signal, etc.)
Upgraded design: relay forwards only QUIC packets addressed to EndpointIds

Two-tier relay:
  Tier 1 (signaling): WebSocket room joins for initial coordination (existing design)
  Tier 2 (packet forwarding): Raw UDP relay for encrypted QUIC packets
  
Tier 2 is what iroh's relay servers do. The relay sees:
  - Source EndpointId (public key): yes (needed for routing)
  - Destination EndpointId: yes (needed for routing)
  - Packet content: NO — all QUIC packets are encrypted
  - What file is being transferred: NO
  - How large the file is: NO
  - Who the peers are (in human terms): NO
```

## 8.2 Relay Rate Limiting Upgrades

Add token bucket rate limiting per EndpointId (not just per IP — avoids IPv6 sharing issues):

```rust
// Per EndpointId limits (fingerprint-based, not IP-based):
const ROOMS_PER_ENDPOINT_PER_HOUR: u32 = 100;
const BYTES_RELAYED_PER_ENDPOINT_PER_HOUR: u64 = 50 * 1024 * 1024 * 1024; // 50GB
const MAX_CONCURRENT_RELAY_SESSIONS_PER_ENDPOINT: u32 = 5;

// Global relay limits:
const MAX_TOTAL_RELAY_SESSIONS: u32 = 10_000;
const MAX_RELAY_BANDWIDTH_MBPS: u32 = 10_000; // 10 Gbps
```

## 8.3 Relay Geographic Distribution

Upgrade from single relay to geo-distributed for latency:

```
Recommended relay geography (Fly.io regions, free tier has 3 VMs):
  sin  → Singapore (Asia-Pacific)
  lax  → Los Angeles (Western Americas)  
  ams  → Amsterdam (Europe)

Client relay selection:
  Measure latency to all 3 on first run → cache in config
  Re-measure every 24h
  Switch to closest relay automatically
  
All 3 relays share no state (rooms are short-lived, 10 minute TTL)
A pair always uses the same relay for their session (relay URL in the pairing QR code)
```

---

# PART 9: UPGRADED CLI DESIGN

## 9.1 New Commands (Gaps in Original Plan)

```bash
# Fast deduplication probe before commit
arc send photo.jpg --probe
# Output: "photo.jpg: already present on iPhone 15 Pro (fast hash match). Transfer? [y/N]"

# Named pipe / stdin streaming (use case: pipeline transfer)
tar cf - ./project | arc send --stdin --name project.tar --to iPhone
# Complement: arc receive > project.tar

# Transfer queue (batch)
arc queue add photo.jpg video.mp4 doc.pdf --to iPhone
arc queue start     # transfers all queued items, respects bandwidth limit
arc queue status    # shows queue + progress
arc queue cancel    # cancels and clears queue

# Bandwidth limiting (useful on metered connections)
arc config set max_upload_mbps 10     # limit to 10 Mbps
arc send large.zip                   # respects limit

# Verify a received file
arc verify ~/Downloads/photo.jpg --hash <blake3_hash>
# Output: "photo.jpg: OK (BLAKE3 matches)"

# Show relay diagnostics
arc relay status
# Output: Relay: wss://relay.arc.sh | Latency: 23ms | Connected | Direct path: YES

# Device presence ping
arc ping "iPhone 15 Pro"
# Output: "iPhone 15 Pro: reachable (LAN, 2ms)"

# Revoke device
arc peers revoke "old MacBook"
arc panic                         # emergency: wipe all keys
```

## 9.2 Shell Completions (Missing from Original Plan)

```bash
# Auto-generate shell completions from clap
arc completions bash   > /etc/bash_completion.d/arc
arc completions zsh    > ~/.zsh/completions/_arc
arc completions fish   > ~/.config/fish/completions/arc.fish
arc completions nushell > ~/.config/nushell/completions/arc.nu
```

The clap `generate` feature handles this automatically — add it to release workflow.

## 9.3 Non-Interactive / Scripting Mode

```bash
# Machine-readable output for all commands
arc send photo.jpg --to iPhone --json 2>&1 | jq .
# Output:
{
  "status": "ok",
  "transfer_id": "...",
  "bytes_sent": 4823910,
  "duration_ms": 342,
  "speed_mbps": 112.8,
  "path": "direct_quic_lan"
}

arc receive --auto-accept --from "iPhone" --dir ~/Downloads --json
# Accepts without prompt, outputs JSON per received file
```

---

# PART 10: UPGRADED MOBILE APP

## 10.1 Share Extension Memory Limit (iOS) — Upgrade

Original plan notes the 6MB iOS share extension limit. Upgrade strategy:

```
For files > 5MB from iOS share extension:
  1. Extension receives file URL (not data) from OS
  2. Extension launches main app via URL scheme: arc://share?url=file:///...
  3. Main app takes over and handles the transfer
  4. If main app not running: store transfer intent in App Group UserDefaults
  5. On next launch: main app picks up pending intents and resumes

This avoids the 6MB limit entirely by delegating to the main app process.
```

## 10.2 iOS Background Transfer via BGTaskScheduler (Upgrade from UIBackgroundTask)

The original plan proposes `UIApplication.beginBackgroundTask` (30 seconds). Better:

```swift
// Register background task (does not expire like beginBackgroundTask):
BGTaskScheduler.shared.register(
    forTaskWithIdentifier: "sh.arc.transfer",
    using: nil
) { task in
    // Arc transfer runs here — no 30s limit for BGProcessingTask
    ArcTransferManager.shared.resumePendingTransfers {
        task.setTaskCompleted(success: true)
    }
}

// Schedule when transfer starts:
let request = BGProcessingTaskRequest(identifier: "sh.arc.transfer")
request.requiresNetworkConnectivity = true
request.requiresExternalPower = false
BGTaskScheduler.shared.submit(request, error: nil)
```

`BGProcessingTask` is meant for tasks like this — it runs when device is idle with
network. Not guaranteed to run immediately, but survives app kill for large transfers.
For immediate small transfers: still use `beginBackgroundTask` (30 second window).

## 10.3 Notification-Based Wake for Android

For Android background transfers, combine foreground service + WorkManager:

```kotlin
class ArcTransferWorker(context: Context, params: WorkerParameters) : 
    CoroutineWorker(context, params) {
    
    override suspend fun doWork(): Result {
        // Runs even when app is killed, respects Doze mode
        val transferId = inputData.getString("transfer_id") ?: return Result.failure()
        return try {
            ArcTransferEngine.resume(transferId)
            Result.success()
        } catch (e: Exception) {
            if (runAttemptCount < 3) Result.retry() else Result.failure()
        }
    }
}

// Schedule with expedited work for immediate execution:
val request = OneTimeWorkRequestBuilder<ArcTransferWorker>()
    .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
    .setInputData(workDataOf("transfer_id" to id))
    .build()
WorkManager.getInstance(context).enqueue(request)
```

---

# PART 11: UPGRADED TESTING STRATEGY

## 11.1 Add Chaos Engineering Tests (New)

```rust
// tests/chaos/
#[tokio::test]
async fn test_transfer_survives_relay_restart() {
    let relay = spawn_test_relay().await;
    let (sender, receiver) = spawn_pair_via_relay(&relay).await;
    
    let file = create_temp_file(100 * MB);
    let transfer = tokio::spawn(sender.send_file(file));
    
    tokio::time::sleep(Duration::from_millis(500)).await;
    relay.restart().await;  // simulate relay crash mid-transfer
    
    transfer.await.expect("Transfer should survive relay restart");
}

#[tokio::test]
async fn test_transfer_with_packet_reordering() {
    // Use Linux tc netem to simulate 20% packet reordering
    // QUIC should handle this transparently
}

#[tokio::test]
async fn test_transfer_with_burst_loss() {
    // Simulate bursty packet loss (real-world WiFi behavior)
    // tc netem loss 5% 25%   (5% base loss, 25% correlation = burst)
}

#[tokio::test]
async fn test_simultaneous_sends_from_two_devices() {
    // Both devices send to each other simultaneously
    // Tests bidirectional flow without deadlock
}

#[tokio::test]
async fn test_relay_room_integrity_check() {
    // Relay reports 3 members → arc should abort and warn
    let relay = spawn_malicious_relay_that_injects_member().await;
    let result = pair_via_relay(&relay).await;
    assert_eq!(result, Err(ArcError::RelayCompromised));
}
```

## 11.2 Property-Based Tests (More Thorough)

```rust
proptest! {
    // Compression roundtrip for all files
    #[test]
    fn compression_roundtrip(data in any::<Vec<u8>>()) {
        for algo in [CompressionAlgo::Zstd, CompressionAlgo::Lz4, CompressionAlgo::None] {
            let compressed = compress(&data, algo);
            let decompressed = decompress(&compressed, algo);
            assert_eq!(data, decompressed);
        }
    }
    
    // BLAKE3 Merkle tree roundtrip for arbitrary data and chunk sizes
    #[test]
    fn blake3_merkle_roundtrip(
        data in any::<Vec<u8>>(),
        chunk_size in 1_usize..=65536
    ) {
        let tree = MerkleTree::build(&data, chunk_size);
        for (i, chunk) in data.chunks(chunk_size).enumerate() {
            assert!(tree.verify_chunk(i, chunk));
        }
        // Wrong data should fail:
        let mut bad_chunk = data[..chunk_size.min(data.len())].to_vec();
        if !bad_chunk.is_empty() {
            bad_chunk[0] ^= 0xFF;
            assert!(!tree.verify_chunk(0, &bad_chunk));
        }
    }
    
    // Nonce uniqueness across millions of messages
    #[test]
    fn nonce_uniqueness(session_id in 0u32..u32::MAX, messages in 0u32..100_000u32) {
        let nonces: HashSet<[u8; 12]> = (0..messages)
            .map(|i| build_nonce(session_id, i, Direction::ToReceiver))
            .collect();
        assert_eq!(nonces.len(), messages as usize); // all unique
    }
}
```

## 11.3 Benchmark Suite (New)

```rust
// benches/transfer.rs (using criterion)
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_transfer_throughput(c: &mut Criterion) {
    let sizes = [1 * KB, 1 * MB, 10 * MB, 100 * MB, 1 * GB];
    let mut group = c.benchmark_group("transfer_throughput");
    
    for size in sizes {
        group.throughput(criterion::Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("loopback_quic", size),
            &size,
            |b, &size| b.to_async(tokio_rt()).iter(|| async {
                transfer_loopback(size).await
            }),
        );
    }
    group.finish();
}

fn bench_crypto_overhead(c: &mut Criterion) {
    c.bench_function("chacha20_poly1305_1mb", |b| {
        let key = Key::generate();
        let data = vec![0u8; 1 * MB];
        b.iter(|| encrypt_chunk(&key, &data))
    });
    
    c.bench_function("blake3_hash_1mb_parallel", |b| {
        let data = vec![0u8; 1 * MB];
        b.iter(|| blake3::hash(&data))
    });
}
```

---

# PART 12: UPGRADED CRATE VERSIONS AND DEPENDENCIES

## 12.1 Updated Pinned Versions (June 2026)

```toml
[dependencies]
# Async runtime
tokio = { version = "1.40", features = ["full"] }

# Transport — Option A: iroh (recommended)
iroh = "1.0"
iroh-blobs = "0.35"          # BLAKE3 verified streaming

# Transport — Option B: custom quinn (original plan, keep as fallback)
quinn = "0.11"
rustls = "0.23"
rcgen = "0.13"

# Crypto
x25519-dalek = "2.0"
ed25519-dalek = "2.0"
hkdf = "0.12"
chacha20poly1305 = "0.10"
blake3 = { version = "1.5", features = ["rayon"] }  # ADD rayon for parallel hashing!
rand = "0.8"
# Post-quantum (v2 preparation — add now, gate behind feature flag):
pqcrypto-mlkem = "0.3"       # ML-KEM-768 (Kyber) for v2
pqcrypto-mldsa = "0.3"       # ML-DSA (Dilithium) for v2

# Compression (NEW):
zstd = "0.13"                 # Zstandard compression
lz4_flex = "0.11"             # LZ4 (faster, lower ratio)

# Memory mapping (NEW):
memmap2 = "0.9"               # Memory-mapped I/O for large files

# Protocol
serde = { version = "1", features = ["derive"] }
bincode = "2.0"               # NOTE: upgrade from 1.3 to 2.0 — breaking changes!
uuid = { version = "1", features = ["v4"] }
bytes = "1"
bitflags = "2"                # For CapabilityFlags

# Discovery
mdns-sd = "0.11"
stunclient = "0.2"            # Keep for Option B; iroh handles this in Option A

# CLI
clap = { version = "4", features = ["derive"] }
indicatif = "0.17"
crossterm = "0.27"
qrcode = "0.14"

# Clipboard
arboard = "3"

# HTTP/WS (relay)
axum = { version = "0.7", features = ["ws"] }
tower = "0.4"
tokio-tungstenite = "0.23"

# Observability
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json"] }
prometheus = "0.13"

# Storage
sqlx = { version = "0.8", features = ["sqlite", "runtime-tokio"] }  # 0.7 → 0.8

[dev-dependencies]
criterion = { version = "0.5", features = ["async_tokio"] }
proptest = "1.4"
cargo-fuzz = "0.12"           # not a dep — install separately
```

### bincode 2.0 Breaking Changes to Note

bincode 2.0 introduces a new configuration API and changes serialization behavior for
some types. The `bincode::encode_to_vec` / `bincode::decode_from_slice` API replaces
the old `bincode::serialize` / `bincode::deserialize`. Protocol version bump required.

### blake3 rayon Feature

Adding the `rayon` feature to blake3 enables multi-threaded hashing automatically for
large inputs. A 25 GB file: 25 seconds (single-thread) → ~1.5 seconds (8 cores).
Critical for pre-transfer integrity checks on large files.

---

# PART 13: UPGRADED WEEK-BY-WEEK BUILD PLAN (14 Weeks)

## Phase 0: Research Week (Week 0 — New)

```
Week 0 (before coding)
  Day 1: Build iroh echo demo. Understand EndpointId → connects to n0 relay.
  Day 2: Build iroh-blobs send/receive demo. Understand BLAKE3 verified streaming.
  Day 3: Build LocalSend protocol simulation in Rust (REST → HTTPS, mDNS discovery).
          Understand what arc adds vs what these tools cover.
  Day 4: Read all 6 croc CVEs. Trace each to their root cause in code.
          Write a "never do this in arc" document.
  Day 5: Decision: use iroh as transport layer OR build custom quinn+STUN.
          If iroh: read iroh source code for Endpoint, Router, and Relay.
          If custom: prototype the STUN + hole punch pair. If it works in 1 day, proceed.
          Recommendation: use iroh. It works, it's proven, it's 1.0.
```

## Phase 1: Foundation (Weeks 1-2)

```
Week 1
  Day 1-2: Cargo workspace setup with ALL crates
            Add all pinned crate versions, ensure compile
            
  Day 3-5: arc-core crypto module (same as original plan)
            + Add: blake3 rayon parallel hashing tests
            + Add: zstd/lz4 compression roundtrip tests

Week 2
  Day 1-3: Protocol module
            + Upgrade: add CapabilityFlags bitflags
            + Add: CompressedChunk variant
            + Add: bincode 2.0 API (breaking change from original plan)
            + Test: all message variants roundtrip, including new ones

  Day 4-7: Transport foundation
            IF iroh path: Build iroh Endpoint + connect pair over loopback
            IF quinn path: Original plan's QUIC hello world
            + BBRv3 congestion control configured in TransportConfig
```

## Phase 2: Transfer Engine (Weeks 3-4)

```
Week 3
  Day 1-3: BLAKE3 Merkle tree chunker
            + Instead of per-chunk individual BLAKE3 hashes only:
              Build MerkleTree struct that produces root hash + proofs
            + Streaming verification: each chunk verifies against its Merkle proof
            + Unit tests: arbitrary file sizes, verify out-of-order

  Day 4-7: Compression pipeline
            + CompressibilityProbe: sample first 64KB, measure ratio
            + CompressedChunker: wraps Chunker with optional zstd/lz4
            + Test: text files compress 3-10x; JPEGs pass through uncompressed

Week 4 (same as original plan + memory mapping)
  Day 1-4: Receiver + reassembler with memmap2
  Day 5-7: Resume protocol (disk-persisted Merkle bitmap)
```

## Phase 3: Transport + Discovery (Weeks 5-6) — same as original

## Phase 4: CLI Polish (Weeks 7-8)

```
Week 7-8 additions to original plan:
  + arc queue (batch transfer queue)
  + arc verify (BLAKE3 verification of received file)
  + arc ping (peer reachability check)
  + arc relay status (relay diagnostics)
  + arc completions <shell>
  + --json flag on all commands (machine-readable output)
  + arc panic (emergency key wipe)
```

## Phase 5: Robustness + Security (Weeks 9-10)

```
Week 9 addition:
  + Room integrity check (relay MITM detection — abort if >2 members)
  + PQC preparation: add ML-KEM feature flag (disabled by default)
    Implement hybrid key exchange behind `features = ["pqc"]`
    
Week 10 additions:
  + Chaos engineering tests (relay restart, packet loss bursts)
  + Benchmark suite (criterion): throughput vs file size
  + Property-based tests (proptest): compression, Merkle tree, nonces
```

## Phase 6: Mobile + Release (Weeks 11-14)

```
Week 11-12: Mobile app (same as original plan)
Week 13 (NEW — was not in original plan)
  Day 1-2: Performance profiling with cargo flamegraph
            Target: saturate 1 Gbps LAN transfer
            Profile: Where is CPU time going? (crypto? syscalls? copies?)
  Day 3-4: Optimize hot paths
            - Enable GSO in quinn config
            - Verify zero-copy mmap path is actually zero-copy (no hidden buffers)
            - Benchmark ChaCha20-Poly1305 throughput vs AES-GCM-256 (NI)
              If running on AES-NI hardware, AES-GCM is faster — make configurable
  Day 5-7: Documentation
            PROTOCOL.md: full wire format spec including new message types
            SECURITY.md: full threat model with croc CVE retrospective
            SELF_HOSTING.md: relay + iroh relay (or custom relay) deployment

Week 14
  Day 1-3: Final integration testing across all platforms (Linux, macOS, Windows, iOS, Android)
  Day 4-5: Release pipeline verification (GitHub Actions builds all targets)
  Day 6: Tag v0.1.0
  Day 7: Ship
```

---

# PART 14: UPGRADED RISK REGISTER

```
Risk                              │ Like. │ Impact │ Mitigation (Upgraded)
──────────────────────────────────┼───────┼────────┼─────────────────────────────────────
iroh 1.0 API changes after adopt  │ Low   │ High   │ Pin exact iroh version; abstraction
                                  │       │        │ layer means swap is <1 day of work
UDP hole punch fails for ~10% NAT │ High  │ Medium │ Relay fallback; iroh achieves 90%
                                  │       │        │ vs croc's 0% — already better
bincode 2.0 breaking changes      │ High  │ Medium │ Implement in week 2; test thoroughly
                                  │       │        │ before rest of protocol is built on it
iOS BGProcessingTask not scheduled│ Medium│ Medium │ Use UIBackgroundTask (30s) as primary;
                                  │       │        │ BGProcessingTask as best-effort
BBRv3 not available in quinn 0.11 │ Medium│ Low    │ Evaluate TQUIC (supports BBRv3);
                                  │       │        │ or contribute BBRv3 to quinn-proto
ML-KEM crate not production-ready │ Low   │ Low    │ Gated behind feature flag; v1 ships
                                  │       │        │ without it — no impact on v1 release
Relay secret in room ID (croc bug)│ DONE  │ HIGH   │ Arc uses SHA256(nonce) by design
Terminal injection (croc GO-2068) │ DONE  │ HIGH   │ Arc sanitizes filenames before display
Process secret leak (croc GO-2069)│ DONE  │ HIGH   │ Arc uses daemon IPC, never argv secrets
Relay active MITM attack          │ Low   │ High   │ New: room integrity check (>2 = abort)
                                  │       │        │ Equivalent to magic-wormhole "scary"
Large file OOM during hashing     │ Low   │ High   │ Streaming BLAKE3 Merkle tree; memmap2
                                  │       │        │ Never loads full file into memory
Windows Defender false positive   │ High  │ Medium │ Authenticode signing; publish checksum
                                  │       │        │ file + GPG signature on GitHub release
flutter_rust_bridge FFI complexity│ Medium│ High   │ LocalSend proves this works at scale;
                                  │       │        │ LocalSend uses same stack (rhttp + frb)
```

---

# PART 15: FINAL COMPARISON TABLE

```
Feature                        │ croc v10   │ magic-wormhole │ LocalSend │ iroh/sendme │ arc (v1)
───────────────────────────────┼────────────┼────────────────┼───────────┼─────────────┼───────────
Transport                      │ TCP only   │ TCP relay      │ HTTP/HTTPS│ QUIC P2P    │ QUIC P2P
Direct connections (no relay)  │ LAN only   │ Rare           │ LAN only  │ 95% of time │ 90%+ target
NAT traversal                  │ None       │ None           │ None      │ 90%         │ 90%+
WAN support                    │ Yes        │ Yes            │ No        │ Yes         │ Yes
Mobile app                     │ No         │ No             │ Yes (LAN) │ No          │ Yes (LAN+WAN)
Clipboard sync                 │ Basic      │ No             │ Text only │ No          │ Full daemon
Persistent device trust        │ No         │ No             │ TOFU cert │ EndpointId  │ Full pairing
Forward secrecy                │ Partial    │ Partial        │ TLS 1.3   │ Full        │ Full
Post-quantum ready             │ No         │ No             │ No        │ No          │ v2 roadmap
Daemon mode                    │ No         │ No             │ Yes (tray)│ No          │ Yes
Resume on disconnect           │ Yes        │ No             │ No        │ Yes         │ Yes
Compression                    │ No         │ No             │ No        │ No          │ Adaptive
Fast dedup probe               │ Yes(imohash│ No             │ No        │ No          │ Yes(BLAKE3)
Terminal injection safe        │ Fixed 9.6.6│ N/A            │ N/A       │ N/A         │ By design
Secret exposed to relay        │ Fixed 9.6.6│ No             │ N/A       │ No          │ Impossible
Relay MITM detection           │ No         │ Yes("scary")   │ N/A       │ No          │ Yes(integrity)
Language                       │ Go         │ Python/Rust    │ Flutter   │ Rust        │ Rust+Flutter
```

---

*Total upgraded scope: ~6,000 lines of core Rust, ~1,800 lines Flutter, ~600 lines relay.*
*Estimated time: 14 weeks part-time or 7 weeks full-time.*
*The 2 extra weeks (vs original 12) cover: iroh evaluation (Week 0), performance profiling (Week 13), and additional features (queue, verify, panic, completions).*

---

# PART 16: FORMAL THREAT MODEL

## 16.1 Assets and Trust Boundaries

```
Assets (what must be protected)
┌───────────────────────────────────────────────────────────────────┐
│ Asset                    │ Confidentiality │ Integrity │ Avail.  │
│──────────────────────────┼─────────────────┼───────────┼─────────│
│ File content             │ CRITICAL        │ CRITICAL  │ HIGH    │
│ File names               │ HIGH            │ MEDIUM    │ LOW     │
│ File sizes / counts      │ MEDIUM          │ LOW       │ LOW     │
│ Device identities        │ HIGH            │ CRITICAL  │ MEDIUM  │
│ Pairing keys             │ CRITICAL        │ CRITICAL  │ HIGH    │
│ Session keys             │ CRITICAL        │ CRITICAL  │ HIGH    │
│ Transfer metadata        │ MEDIUM          │ LOW       │ LOW     │
│ Communication timing     │ LOW             │ LOW       │ LOW     │
│ Peer graph (who talks)   │ MEDIUM          │ LOW       │ LOW     │
└───────────────────────────────────────────────────────────────────┘

Trust Boundaries
  ┌─────────────────────────────────────────────────────────┐
  │  TRUSTED                                                 │
  │  ┌─────────────┐        ┌─────────────────────────────┐│
  │  │ arc-core    │        │ OS keystore (keychain/DPAPI) ││
  │  │ (our code)  │        │ OS secure memory             ││
  │  └─────────────┘        └─────────────────────────────┘│
  └─────────────────────────────────────────────────────────┘
          │                             │
  ════════╪═════════════════════════════╪═══════ TRUST BOUNDARY
          │                             │
  ┌───────▼─────────────────────────────▼──────────────────┐
  │  UNTRUSTED                                              │
  │  ┌──────────────┐  ┌─────────────┐  ┌────────────────┐│
  │  │ arc-relay    │  │ Network     │  │ Peer device    ││
  │  │ server       │  │ (ISP/WAN)   │  │ (before pair.) ││
  │  └──────────────┘  └─────────────┘  └────────────────┘│
  └────────────────────────────────────────────────────────┘
```

## 16.2 Attacker Classes

```
CLASS   │ CAPABILITY                                   │ GOAL
────────┼──────────────────────────────────────────────┼────────────────────────────
A1      │ Passive ISP / network observer               │ Learn who transfers to whom
        │ Can read all unencrypted packets              │ and what file sizes/times
        │ Cannot modify packets                        │
────────┼──────────────────────────────────────────────┼────────────────────────────
A2      │ Active network adversary                     │ MITM, inject packets,
        │ Can read, modify, replay, delay packets       │ replay attacks
        │ Cannot break TLS/QUIC                        │
────────┼──────────────────────────────────────────────┼────────────────────────────
A3      │ Malicious relay operator                     │ Learn peer identities,
        │ Controls relay server completely             │ correlation attacks,
        │ Can delay/drop relay traffic                  │ fake relay messages
────────┼──────────────────────────────────────────────┼────────────────────────────
A4      │ Compromised peer device (post-pairing)       │ Exfiltrate future session keys
        │ Full access to paired device's keystore      │ Impersonate paired device
────────┼──────────────────────────────────────────────┼────────────────────────────
A5      │ Local malware on sender/receiver             │ Read clipboard, steal files
        │ Runs as same user as arc                     │ before encryption
────────┼──────────────────────────────────────────────┼────────────────────────────
A6      │ Rogue LAN attacker                           │ Inject mDNS records,
        │ On same local network segment                │ intercept LAN transfers
────────┼──────────────────────────────────────────────┼────────────────────────────
A7      │ Quantum adversary (future, v2 scope)         │ Break X25519, Ed25519
        │ CRQC available                               │ via Shor's algorithm
────────┼──────────────────────────────────────────────┼────────────────────────────
A8      │ State-level adversary                        │ Traffic analysis,
        │ Controls BGP, can reroute traffic            │ endpoint correlation,
        │ Can compel relay operator legally            │ compelled disclosure
```

## 16.3 STRIDE Analysis per Component

```
COMPONENT: arc-relay
  S (Spoofing):         Attacker joins room with guessed room ID
    ↳ Mitigation: 256-bit room ID (SHA256 of nonce) — brute force infeasible
  T (Tampering):        Relay modifies signaling messages
    ↳ Mitigation: Signaling payload encrypted with pairing_key — relay cannot modify
  R (Repudiation):      Relay denies forwarding a message
    ↳ Mitigation: Not in scope for v1 (no guaranteed delivery receipts)
  I (Info Disclosure):  Relay reads signaling payload
    ↳ Mitigation: Payload encrypted; relay sees only opaque ciphertext
  D (Denial of Service): Relay drops connections or delays traffic
    ↳ Mitigation: Fallback relay URLs; local relay detection; auto-reconnect
  E (Elevation):        Relay gains access to file content
    ↳ Mitigation: E2E encryption — relay only proxies ciphertext

COMPONENT: LAN discovery (mDNS)
  S (Spoofing):         Attacker sends fake mDNS record for a device
    ↳ Mitigation: mDNS only provides IP:port; authentication happens at QUIC layer
                  A spoofed mDNS entry will fail the Ed25519 auth challenge
  T (Tampering):        Attacker corrupts mDNS packets
    ↳ Mitigation: mDNS is advisory — QUIC auth is the real check
  I (Info Disclosure):  mDNS records expose device name and device_id
    ↳ Mitigation: v1 accepts this; v2 should use ephemeral mDNS names
  D (Denial of Service): mDNS storm or flooding
    ↳ Mitigation: Discovery timeout 100ms; fallback to relay path

COMPONENT: Pairing handshake
  S (Spoofing):         Attacker replaces peer's ephemeral public key
    ↳ Mitigation: Fingerprint verification provides OOB confirmation
  T (Tampering):        Relay substitutes its own pubkey for peer's
    ↳ Mitigation: Fingerprint verification (emoji) — user confirms OOB
  I (Info Disclosure):  Pairing nonce leaked via process args
    ↳ Mitigation: Nonce in keystore memory, never in argv (croc GO-2023-2069 fix)
  E (Elevation):        Attacker pairs device without user consent
    ↳ Mitigation: Physical access required for QR scan or code entry

COMPONENT: File transfer
  T (Tampering):        In-transit chunk modification
    ↳ Mitigation: BLAKE3 Merkle-tree verification per chunk + whole-file
  I (Info Disclosure):  Filename exposed to relay
    ↳ Mitigation: Filename encrypted within TLS+ChaCha20 envelope
  I (Info Disclosure):  File size visible to relay
    ↳ Mitigation: Relay sees stream bytes only; actual file size obfuscated by padding
  T (Tampering):        Path traversal in received filename (croc GO-2023-2071 fix)
    ↳ Mitigation: Strip all `..` components before writing; whitelist path separators
  T (Tampering):        Sender injects new files mid-transfer (croc GO-2023-2073 fix)
    ↳ Mitigation: TransferOffer is immutable after acceptance
```

## 16.4 Attack Trees

```
GOAL: Attacker reads transferred file content
├── Break TLS 1.3 / QUIC encryption
│   └── Infeasible (no known attack)
├── Compromise relay server
│   └── Relay sees only ChaCha20-Poly1305 ciphertext → still infeasible
├── MITM the initial pairing
│   ├── Relay substitutes ephemeral pubkey
│   │   └── Blocked by: fingerprint verification (OOB)
│   └── Physical proximity attack (QR code interception)
│       └── Requires physical presence during pairing
├── Compromise device keystore
│   └── Attacker gains pairing keys
│       └── Mitigation: OS keystore (Keychain/DPAPI) + hardware-backed on mobile
│           └── Past sessions: protected by forward secrecy (ephemeral X25519)
└── Malware on sender/receiver
    └── Reads file before encryption (pre-encryption intercept)
        └── Out of scope — arc is a transport, not a malware scanner

GOAL: Attacker determines WHO is transferring to WHOM
├── Monitor relay connections (relay operator knows room IDs)
│   └── Room ID = SHA256(nonce) — reveals nothing without nonce
│       └── Partial: two connections arrived in same room = same session
│           └── Mitigation: room IDs are opaque; timing alone reveals pairing
├── Monitor LAN mDNS broadcasts
│   └── mDNS reveals device names on LAN
│       └── v1 accepts this; v2: ephemeral mDNS names per session
└── Traffic analysis on relay (timing correlation)
    └── Mitigation: cover traffic + padding (see §18)
```

## 16.5 Security Invariants (Checkable Per Protocol Message)

These invariants must hold for every protocol message. Verify during code review:

```
INV-1: File content MUST NOT appear outside ChaCha20-Poly1305 ciphertext
INV-2: File names MUST NOT appear in relay-visible signaling messages
INV-3: Device identities MUST NOT be disclosed to untrusted parties before pairing
INV-4: Session keys MUST be derived from ephemeral material (forward secrecy)
INV-5: Nonces MUST NOT repeat within a session (direction-flag + index encoding)
INV-6: Room IDs MUST NOT contain or derive from the raw pairing nonce
INV-7: Filenames MUST be sanitized of control characters BEFORE any display
INV-8: File paths MUST be validated to not traverse outside the destination directory
INV-9: A relay room with > 2 members MUST cause immediate abort by both clients
INV-10: Secrets MUST NOT appear in process argv, env vars, or log output
```

## 16.6 Abuse Cases

```
ABUSE-1: User sends ransomware disguised as photo.jpg
  Arc's position: transport layer, not content scanner
  Response: Document clearly; add optional checksum verification in UX

ABUSE-2: Attacker sends 1TB file to fill disk
  Mitigation: Receiver checks disk space before each chunk (already in plan)
  Add: Configurable max_single_file_size and max_transfer_session_size limits

ABUSE-3: Attacker spams relay with 10,000 room creations per second
  Mitigation: IP rate limiting (10/min, 100/hr) — already in plan
  Add: PoW (Proof of Work) puzzle for room creation under load
        Simple: SHA256(room_id || nonce) must start with 4 zero bits
        Cost to attacker: ~16 hashes per room creation
        Cost to legitimate user: imperceptible (<1ms)

ABUSE-4: Attacker replays an old pairing QR code found on screenshot
  Mitigation: Pairing nonce expires after 10 minutes (already in plan)
  Add: Nonce is single-use — relay marks used nonces for 10 minutes

ABUSE-5: Malicious peer sends filename containing ANSI escape sequences
  Mitigation: INV-7 (control char stripping) — every display path sanitized
  Verify: Write a test that sends ESC[2J (clear screen) as filename
          and asserts it is displayed as safe_display_name("ESC?2J")

ABUSE-6: Clipboard sync loop (A copies → B syncs → A receives B's echo)
  Mitigation: Sequence numbers + source device ID deduplication (already in plan)
  Verify: Property test — if A and B sync N times simultaneously, no message loops
```

---

# PART 17: FORMAL PROTOCOL SPECIFICATION

## 17.1 Session State Machine

Every arc session MUST follow this state machine. Implementations that deviate
MUST be treated as protocol errors and connections MUST be closed.

```
                    ┌─────────────────────────────────────────────┐
                    │           ARC SESSION STATE MACHINE          │
                    └─────────────────────────────────────────────┘

  ┌─────────┐  transport    ┌────────────┐  Hello+      ┌────────────────┐
  │  IDLE   │ ─connected──► │ CONNECTED  │ ─HelloAck──► │ AUTHENTICATING │
  └─────────┘               └────────────┘              └────────────────┘
       ▲                          │                             │
       │                     any error                   AuthOk/AuthFail
       │                          │                             │
       │                          ▼                    ┌────────▼─────────┐
       │                     ┌────────┐  AuthFail       │   NEGOTIATING    │
       └─────────────────────│ CLOSED │◄────────────────│  (Capabilities)  │
                             └────────┘                 └────────┬─────────┘
                                  ▲                              │
                                  │                    TransferAccept
                                  │                              │
                                  │                    ┌─────────▼────────┐
                                  │       TransAbort   │   TRANSFERRING   │
                                  └────────────────────│                  │
                                                        │  Chunk exchange  │
                                                        │  Integrity check │
                                                        └─────────┬────────┘
                                                                  │
                                                        TransferComplete
                                                                  │
                                                        ┌─────────▼────────┐
                                                        │   COMPLETING     │
                                                        │  Final BLAKE3    │
                                                        │  verification    │
                                                        └─────────┬────────┘
                                                                  │
                                                        ┌─────────▼────────┐
                                                        │   IDLE_READY     │
                                                        │  (same session,  │
                                                        │   next transfer) │
                                                        └──────────────────┘
```

## 17.2 State Transition Table

```
State           │ Trigger                  │ Next State    │ Action
────────────────┼──────────────────────────┼───────────────┼────────────────────────────
IDLE            │ Outbound connect         │ CONNECTED     │ Open QUIC conn; send Hello
IDLE            │ Inbound connection       │ CONNECTED     │ Receive Hello; send HelloAck
CONNECTED       │ Hello received (OK ver.) │ AUTHENTICATING│ Send AuthChallenge
CONNECTED       │ Hello bad version        │ CLOSED        │ Send AuthFail(version); close
CONNECTED       │ Transport error          │ CLOSED        │ Log; clean up temp files
AUTHENTICATING  │ AuthResponse (valid sig) │ NEGOTIATING   │ Send AuthOk; exchange caps
AUTHENTICATING  │ AuthResponse (bad sig)   │ CLOSED        │ Send AuthFail(bad_sig); close
AUTHENTICATING  │ AuthResponse timeout 5s  │ CLOSED        │ Send AuthFail(timeout); close
NEGOTIATING     │ TransferOffer received   │ TRANSFERRING  │ Send TransferAccept or Reject
NEGOTIATING     │ TransferOffer sent       │ TRANSFERRING  │ Await TransferAccept
NEGOTIATING     │ Peer sends Goodbye       │ CLOSED        │ Acknowledge; close gracefully
TRANSFERRING    │ All chunks received+OK   │ COMPLETING    │ Verify BLAKE3 root
TRANSFERRING    │ ChunkNak (retry limit)   │ CLOSED        │ Send TransferAbort(corrupt)
TRANSFERRING    │ Disconnect (reconnect)   │ IDLE          │ Persist resume state to disk
TRANSFERRING    │ Disk full                │ CLOSED        │ Send TransferAbort(disk_full)
COMPLETING      │ BLAKE3 root matches      │ IDLE_READY    │ Atomic rename; notify user
COMPLETING      │ BLAKE3 root mismatch     │ CLOSED        │ Delete temp; notify user
IDLE_READY      │ New TransferOffer        │ TRANSFERRING  │ Start new transfer (same conn)
IDLE_READY      │ Goodbye                  │ CLOSED        │ Close gracefully
ANY             │ Ping                     │ Same          │ Send Pong immediately
ANY             │ Room member count > 2    │ CLOSED        │ TransferAbort(relay_tampered)
```

## 17.3 Message Legality per State

Messages received in unexpected states MUST be rejected with a protocol error:

```rust
pub fn validate_message_for_state(
    msg: &ArcMessage,
    state: &SessionState,
) -> Result<(), ProtocolError> {
    match (state, msg) {
        // CONNECTED: only Hello/HelloAck allowed
        (SessionState::Connected, ArcMessage::Hello { .. }) => Ok(()),
        (SessionState::Connected, ArcMessage::HelloAck { .. }) => Ok(()),
        // AUTHENTICATING: only AuthChallenge/AuthResponse/AuthOk/AuthFail
        (SessionState::Authenticating, ArcMessage::AuthChallenge { .. }) => Ok(()),
        (SessionState::Authenticating, ArcMessage::AuthResponse { .. }) => Ok(()),
        (SessionState::Authenticating, ArcMessage::AuthOk) => Ok(()),
        (SessionState::Authenticating, ArcMessage::AuthFail { .. }) => Ok(()),
        // TRANSFERRING: only transfer-related and Ping
        (SessionState::Transferring, ArcMessage::Chunk { .. }) => Ok(()),
        (SessionState::Transferring, ArcMessage::ChunkAck { .. }) => Ok(()),
        (SessionState::Transferring, ArcMessage::ChunkNak { .. }) => Ok(()),
        (SessionState::Transferring, ArcMessage::TransferComplete { .. }) => Ok(()),
        (SessionState::Transferring, ArcMessage::TransferAbort { .. }) => Ok(()),
        (SessionState::Transferring, ArcMessage::Ping { .. }) => Ok(()),
        (SessionState::Transferring, ArcMessage::Pong { .. }) => Ok(()),
        // Ping/Pong: always legal
        (_, ArcMessage::Ping { .. }) => Ok(()),
        (_, ArcMessage::Pong { .. }) => Ok(()),
        // Everything else: illegal transition
        (state, msg) => Err(ProtocolError::IllegalMessageForState {
            state: state.clone(),
            message_type: msg.type_name(),
        }),
    }
}
```

## 17.4 Timeout Budget

```
Timeout                          │ Duration │ Action on expiry
─────────────────────────────────┼──────────┼────────────────────────────────
QUIC handshake                   │ 10s      │ Try TCP fallback
Hello → HelloAck                 │ 5s       │ Close connection; retry
AuthChallenge → AuthResponse     │ 5s       │ Close; AuthFail(timeout)
TransferOffer → TransferAccept   │ 30s      │ Close; TransferAbort(no_response)
  (user must accept)             │          │ (user has 30s to tap "Accept")
Chunk → ChunkAck                 │ 10s      │ Retransmit (max 3 retries)
Ping keep-alive                  │ 15s      │ No Pong → consider disconnected
Reconnect attempt                │ 30s      │ Exponential backoff starts
Total reconnect window           │ 300s     │ After 5 min, abandon + notify user
Pairing nonce                    │ 600s     │ Mark nonce used; reject new rooms
```

---

# PART 18: METADATA PRIVACY

## 18.1 What the Relay Learns (Even with E2E Encryption)

Even with perfect end-to-end encryption, a relay can observe:

```
Observable to relay (even with arc's current design):
  - Two endpoints joined the same room at timestamps T1 and T2
  - The relay proxied N bytes between them over D seconds
  - Connection dropped at timestamp T3
  - The endpoints' IP addresses (unless behind VPN)

What this reveals (traffic analysis):
  - "IP X.X.X.X and IP Y.Y.Y.Y communicate regularly" → social graph
  - "Session was 2.3 GB over 19 seconds" → file size estimate
  - "Session pattern matches daily backup at 2am" → behavioral fingerprint
```

## 18.2 Padding Strategy (Hides File Sizes)

Add configurable padding to obscure transfer sizes:

```rust
pub enum PaddingMode {
    /// No padding — fastest, least private (default for LAN)
    None,
    
    /// Pad to nearest power of 2 in MB
    /// 1.1 GB → padded to 2 GB (max 2x overhead)
    PowerOfTwo,
    
    /// Pad to nearest multiple of chunk_size
    /// Minimal overhead, hides size within chunk granularity
    ChunkAligned,
    
    /// Full padding to a fixed size cap (maximum privacy)
    /// All transfers appear to be exactly `cap` bytes
    /// Only useful for small files where cap >> actual size
    Fixed { cap: u64 },
}

// Padding implementation: append random bytes (authenticated)
// Receiver knows total_size from TransferOffer; discards padding bytes
// Padding bytes MUST be random (not zeros — zero-padding is compressible/distinguishable)
// Padding MUST be covered by ChaCha20-Poly1305 authentication
```

Default mode: `ChunkAligned` for all paths.
Advanced mode: `PowerOfTwo` for users who want stronger size privacy.

## 18.3 Control Packet Padding (Hides Message Types)

Short control packets (AuthOk = ~10 bytes) are distinguishable from
Chunk packets (~8MB) by size alone. Pad ALL packets to a fixed size before encryption:

```
Control packets: pad to 512 bytes
Chunk packets:   pad to chunk_size (already uniform)

After padding, every wire packet is either:
  - Exactly 512 bytes (control)
  - Exactly chunk_size bytes (data)

A relay observer cannot distinguish AuthOk from ChunkAck.
```

```rust
const CONTROL_PADDED_SIZE: usize = 512;

fn pad_control_message(msg: &[u8]) -> Vec<u8> {
    debug_assert!(msg.len() <= CONTROL_PADDED_SIZE);
    let mut padded = msg.to_vec();
    let pad_len = CONTROL_PADDED_SIZE - msg.len();
    // Append pad_len as u16 LE at bytes [510..512], rest is random
    padded.extend(rand::random::<[u8; pad_len.max(2) - 2]>()); // body
    padded.extend(&(pad_len as u16).to_le_bytes()); // length indicator
    padded
}
```

The receiver reads the last 2 bytes to find pad_len, then strips it.

## 18.4 Cover Traffic (Optional Daemon Mode)

When arc daemon is running with `cover_traffic = true`, it sends heartbeat
traffic to the relay at regular intervals to obscure when real transfers happen:

```toml
[daemon]
cover_traffic = false          # default off (battery/bandwidth cost)
cover_traffic_interval_ms = 5000
cover_traffic_size_bytes = 512  # same as control packet size — indistinguishable
```

Cover traffic is a dummy QUIC datagram (not a stream packet) encrypted with
a session key. The relay cannot distinguish it from a real control message.

## 18.5 Timing Obfuscation (Optional)

Add a small random delay (0–50ms) to all outbound messages when `timing_obfuscation = true`.
This prevents timing correlation attacks where an adversary correlates message timing
on sender side with message arrival on relay side to fingerprint the session.

---

# PART 19: CRYPTOGRAPHIC AGILITY

## 19.1 CipherSuite Architecture

Replace hardcoded algorithms with negotiated suite identifiers:

```rust
/// Cipher suites negotiated in Hello message
#[repr(u16)]
pub enum CipherSuite {
    /// v1 default: classical, high-speed
    X25519_ChaCha20Poly1305_BLAKE3_Ed25519 = 0x0001,
    
    /// v1 alt: AES-NI hardware acceleration path (faster on x86 with AES-NI)
    X25519_AES256GCM_BLAKE3_Ed25519 = 0x0002,
    
    /// v2: post-quantum hybrid
    X25519_MLKEM768_ChaCha20Poly1305_BLAKE3_MLDSA65 = 0x0101,
    
    /// v2 alt: PQ + AES-NI
    X25519_MLKEM768_AES256GCM_BLAKE3_MLDSA65 = 0x0102,
}

impl CipherSuite {
    /// Returns the key exchange algorithm
    pub fn kem(&self) -> KEM { ... }
    
    /// Returns the symmetric AEAD algorithm
    pub fn aead(&self) -> AEAD { ... }
    
    /// Returns the hash/integrity algorithm
    pub fn hash(&self) -> HashAlgo { ... }
    
    /// Returns the signature algorithm
    pub fn sig(&self) -> SigAlgo { ... }
    
    /// Returns whether this suite provides post-quantum security
    pub fn is_post_quantum(&self) -> bool {
        matches!(self,
            CipherSuite::X25519_MLKEM768_ChaCha20Poly1305_BLAKE3_MLDSA65 |
            CipherSuite::X25519_MLKEM768_AES256GCM_BLAKE3_MLDSA65
        )
    }
}
```

## 19.2 Suite Negotiation in Hello

```rust
Hello {
    version: u16,
    device_id: [u8; 32],
    nonce: [u8; 32],
    supported_suites: Vec<CipherSuite>,   // sender's preference list, highest first
}

HelloAck {
    version: u16,
    device_id: [u8; 32],
    nonce: [u8; 32],
    selected_suite: CipherSuite,          // receiver picks from intersection
}
```

**Suite selection rule**: Receiver picks the highest-preference suite from sender's list
that the receiver also supports. If no common suite exists: AuthFail(no_common_suite).

## 19.3 AES-256-GCM vs ChaCha20-Poly1305 Auto-Detection

```rust
pub fn preferred_aead() -> AEAD {
    // Check for hardware AES-NI support at runtime:
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("aes") {
        // AES-NI present: AES-256-GCM is faster (~15 GB/s vs ~4 GB/s ChaCha20)
        return AEAD::Aes256Gcm;
    }
    // No AES-NI (ARM, RISC-V, older x86): ChaCha20 is faster and constant-time
    AEAD::ChaCha20Poly1305
}
```

On Apple M-series, AES hardware is present → AES-GCM faster.
On Android phones without AES hardware → ChaCha20 faster.
Auto-detection means arc always uses the faster algorithm for the current device.

---

# PART 20: CAPABILITY NEGOTIATION — TLV UPGRADE

## 20.1 Replace bitflags with Type-Length-Value

bitflags break when adding new capabilities to older clients. TLV is forward-compatible:

```rust
/// TLV-encoded capability
pub struct CapabilityTLV {
    /// 2-byte type identifier
    pub cap_type: CapabilityType,
    /// Variable-length value (0 bytes for boolean flags)
    pub value: CapabilityValue,
}

#[repr(u16)]
pub enum CapabilityType {
    // Transport capabilities
    QuicMultipath         = 0x0001,
    DirectConnection      = 0x0002,
    ConnectionMigration   = 0x0003,

    // Compression capabilities
    CompressionZstd       = 0x0100,  // value: max_level: u8
    CompressionLz4        = 0x0101,

    // Transfer capabilities
    Blake3VerifiedStreaming= 0x0200,
    ContentDefinedChunking= 0x0201,
    DeltaTransfer         = 0x0202,
    SparseFileSupport     = 0x0203,
    ReflinkSupport        = 0x0204,

    // Crypto capabilities
    PostQuantumHybrid     = 0x0300,  // value: supported ML-KEM variants
    AesNiAvailable        = 0x0301,

    // Feature capabilities
    ClipboardSync         = 0x0400,
    DaemonMode            = 0x0401,
    BatchTransfer         = 0x0402,

    // Unknown capability types: MUST be ignored by receiver
    // This makes all future capability additions backward-compatible
}

pub enum CapabilityValue {
    /// Boolean flag (TLV length = 0)
    Flag,
    /// u8 parameter (TLV length = 1)
    U8(u8),
    /// u32 parameter (TLV length = 4)
    U32(u32),
    /// Raw bytes
    Bytes(Vec<u8>),
}
```

## 20.2 TLV Encoding

```
Wire format:
  ┌────────┬────────┬──────────────┐
  │ Type   │ Length │ Value        │
  │ 2 bytes│ 2 bytes│ Length bytes │
  └────────┴────────┴──────────────┘

Example: CompressionZstd with max_level=9
  02 00  (type = 0x0002 LE)
  01 00  (length = 1)
  09     (value = 9)

Example: QuicMultipath (boolean flag)
  01 00  (type = 0x0001 LE)
  00 00  (length = 0, no value bytes)
```

**Unknown type handling**: If receiver sees a capability type it doesn't recognize,
it MUST skip it (skip `length` bytes) and continue parsing. This is the key difference
from bitflags — new capabilities added in future versions are silently ignored by
older clients rather than causing parse errors.

---

# PART 21: TRANSPORT SCHEDULER

## 21.1 Priority Classes

Multiple concurrent transfers must be prioritized. Without a scheduler, a 10 GB
backup transfer will saturate the connection and make clipboard sync unusable:

```rust
#[repr(u8)]
pub enum TransferPriority {
    /// Control messages, Ping/Pong, AuthChallenge
    /// MUST send immediately regardless of backpressure
    Critical = 0,

    /// Clipboard sync, small files < 1MB, user-interactive
    /// Target: < 100ms latency
    Realtime = 1,

    /// Normal file transfers, user-initiated
    /// Target: maximum throughput
    Normal = 2,

    /// Background/queued transfers, daemon-initiated
    /// Target: yield to all other traffic
    Background = 3,
}
```

## 21.2 Scheduler Design

```rust
pub struct TransferScheduler {
    /// Per-priority queues of chunks ready to send
    queues: [VecDeque<ChunkTask>; 4],
    
    /// Weighted Fair Queuing weights per priority:
    /// Critical: always drain first (weight = ∞)
    /// Realtime: drain 8 chunks before 1 Normal chunk
    /// Normal:   drain 4 chunks before 1 Background chunk
    /// Background: drain remainder
    weights: [u32; 4],  // [∞, 8, 4, 1]
    
    /// Current QUIC send budget (tokens from congestion control)
    send_budget: u64,
}

impl TransferScheduler {
    pub fn next_chunk(&mut self) -> Option<ChunkTask> {
        // Always drain Critical first
        if let Some(task) = self.queues[0].pop_front() { return Some(task); }
        
        // Weighted round-robin for Realtime/Normal/Background
        // WFQ ensures clipboard never starves during large transfers
        self.weighted_fair_next()
    }
}
```

## 21.3 QUIC Stream Priority Mapping

Quinn supports stream priorities natively. Map TransferPriority to QUIC priorities:

```rust
use quinn::SendStream;

fn configure_stream_priority(
    stream: &mut SendStream,
    priority: TransferPriority,
) {
    // Quinn priority: higher integer = higher priority
    let quic_priority = match priority {
        TransferPriority::Critical   => i32::MAX,
        TransferPriority::Realtime   => 1000,
        TransferPriority::Normal     => 100,
        TransferPriority::Background => 0,
    };
    stream.set_priority(quic_priority).ok();
}
```

This means the QUIC layer itself (not just application logic) prioritizes
clipboard chunks over backup chunks at the packet scheduling level.

---

# PART 22: ADAPTIVE CONGESTION CONTROL

## 22.1 Algorithm Selection

```rust
pub enum CongestionAlgorithm {
    /// Default for most conditions: good throughput + low buffer bloat
    Bbr3,
    
    /// Fallback for environments where BBR is unfair (shared bottlenecks)
    Cubic,
    
    /// For very high-latency paths (satellite > 500ms RTT)
    /// BBR's probe cycles work better than CUBIC's AIMD on high-latency paths
    BbrHighLatency,
    
    /// For real-time paths (clipboard sync, < 50ms target latency)
    /// Smaller cwnd, faster reaction to loss
    BbrLowLatency,
    
    /// Automatic: pick based on measured RTT and loss
    Auto,
}

pub fn select_congestion_algorithm(
    rtt_ms: u32,
    packet_loss_pct: f32,
    path_type: PathType,
) -> CongestionAlgorithm {
    match (rtt_ms, packet_loss_pct, path_type) {
        // High latency (satellite, cross-continental)
        (rtt, _, _) if rtt > 200 => CongestionAlgorithm::BbrHighLatency,
        // High loss (mobile, bad WiFi)
        (_, loss, _) if loss > 3.0 => CongestionAlgorithm::Bbr3,
        // Real-time path (clipboard)
        (_, _, PathType::RealtimeClipboard) => CongestionAlgorithm::BbrLowLatency,
        // LAN path (very low RTT)
        (rtt, _, PathType::Lan) if rtt < 5 => CongestionAlgorithm::Cubic,
        // Default
        _ => CongestionAlgorithm::Bbr3,
    }
}
```

## 22.2 Path Probing for Multipath

When multiple paths are available (WiFi + LTE), probe both before committing:

```
Path quality probe (run on connect, repeat every 30s):
  Send 10 probe packets on each path
  Measure: RTT, jitter, packet loss rate
  
Path selection policy:
  Primary path:   lowest RTT + lowest loss
  Secondary path: second-best (kept alive, used if primary degrades)
  
Automatic failover:
  If primary RTT increases > 2x baseline for 3 consecutive RTTs:
    → Switch primary and secondary
  If primary loss > 5% for 5 consecutive seconds:
    → Switch primary and secondary
```

---

# PART 23: FILESYSTEM INTELLIGENCE

## 23.1 Sparse File Support

```rust
/// Detect if file has holes (sparse regions)
pub fn is_sparse_file(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(path)?;
        // st_blocks is in 512-byte units; compare to file size
        let actual_blocks = meta.blocks() * 512;
        let apparent_size = meta.len();
        actual_blocks < apparent_size  // fewer actual blocks = sparse
    }
    #[cfg(windows)]
    {
        // DeviceIoControl with FSCTL_GET_RETRIEVAL_POINTERS
        // Checks for FILE_ATTRIBUTE_SPARSE_FILE
        is_sparse_windows(path)
    }
}

/// Transfer sparse file efficiently: send only non-hole extents
pub fn enumerate_extents(path: &Path) -> Vec<FileExtent> {
    #[cfg(linux)]
    // Use SEEK_DATA / SEEK_HOLE (POSIX.1-2008) to find non-hole extents
    {
        let mut extents = Vec::new();
        let mut pos = 0u64;
        loop {
            let data_start = file.seek(SeekFrom::Start(pos))?;
            if data_start == SeekFrom::Hole { break; }
            let hole_start = file.seek(SeekFrom::Hole_from(data_start))?;
            extents.push(FileExtent { offset: data_start, length: hole_start - data_start });
            pos = hole_start;
        }
        extents
    }
}
```

For a 10 GB sparse file (e.g., a VM disk image) that is 90% holes, arc transfers
only the ~1 GB of actual data. Receiver recreates the sparse structure:

```rust
// Receiver side: create sparse file and only write actual extents
fn write_sparse_file(path: &Path, extents: &[FileExtent], data: &[u8]) {
    let file = OpenOptions::new().write(true).create(true).open(path)?;
    file.set_len(total_size)?;  // pre-allocate without writing (creates hole)
    for extent in extents {
        file.seek(SeekFrom::Start(extent.offset))?;
        file.write_all(&data[extent.data_range()])?;
        // Unwritten regions remain as holes
    }
}
```

## 23.2 Hard Link Detection and Deduplication

```rust
/// Track inodes to detect hard links during directory transfer
pub struct InodeTracker {
    seen: HashMap<(u64, u64), String>,  // (dev, ino) → first path seen
}

impl InodeTracker {
    pub fn track(&mut self, path: &Path) -> HardLinkResult {
        let meta = fs::metadata(path)?;
        let key = (meta.dev(), meta.ino());
        
        if let Some(first_path) = self.seen.get(&key) {
            // Hard link: already transferred this inode
            HardLinkResult::LinkTo(first_path.clone())
        } else {
            self.seen.insert(key, path.to_string_lossy().to_string());
            HardLinkResult::NewFile
        }
    }
}

// Wire: instead of re-transferring data, send a CreateHardLink message
CreateHardLink {
    transfer_id: Uuid,
    target_path: String,   // path already on receiver
    link_path: String,     // new path to create as hard link
}
```

This deduplicates hard-linked files in directory transfers (common in Node.js
`node_modules/` and macOS application bundles).

## 23.3 Extended Attributes, ACLs, Resource Forks

```rust
pub struct ExtendedMetadata {
    /// Unix permissions (rwxrwxrwx) — only meaningful if same OS type
    unix_mode: Option<u32>,
    
    /// POSIX ACLs (Linux/macOS extended permissions)
    acl: Option<Vec<u8>>,  // serialized platform ACL
    
    /// Extended attributes
    xattrs: HashMap<String, Vec<u8>>,
    
    /// macOS resource fork (Finder info, custom icons, etc.)
    resource_fork: Option<Vec<u8>>,
    
    /// Windows alternate data streams (ADS)
    alternate_data_streams: HashMap<String, Vec<u8>>,
    
    /// macOS Spotlight metadata (com.apple.metadata:*)
    spotlight_xattrs: HashMap<String, Vec<u8>>,
}

// Transfer policy:
// Cross-OS: skip ACLs and resource forks (incompatible)
// Same OS: transfer all extended metadata
// Config: xattr_policy = "preserve" | "skip" | "ask"
```

## 23.4 Reflink / Copy-on-Write Support

On filesystems that support it (Btrfs, APFS, XFS with reflink), the receiver
can request a reflink rather than a full data copy when the source and destination
are on the same device — instant "copy" that shares blocks:

```rust
// Receiver capability: CapabilityType::ReflinkSupport
// If sender and receiver are on same machine (loopback transfer) and both
// support reflinks, send only the file metadata + BLAKE3 hash.
// Receiver does:
#[cfg(linux)]
fn reflink(src: &Path, dst: &Path) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let src = File::open(src)?;
    let dst = File::create(dst)?;
    // FICLONE ioctl: creates instant reflink on Btrfs/XFS
    unsafe {
        libc::ioctl(dst.as_raw_fd(), FICLONE, src.as_raw_fd());
    }
    Ok(())
}
```

---

# PART 24: DELTA TRANSFER — FULL CHAPTER

## 24.1 Why Fixed-Size Chunking Fails for Delta

Arc v1 uses fixed 1–8MB chunks. For delta transfers, fixed chunks are inefficient:

```
Original file: [AAAA][BBBB][CCCC][DDDD]  (4 x 1MB chunks)
Modified file: [XXXX][AAAA][BBBB][CCCC][DDDD]  (1MB inserted at start)

With fixed chunks:
  Chunk 0: XXXX != AAAA → transfer (1MB)
  Chunk 1: AAAA != BBBB → transfer (1MB)
  Chunk 2: BBBB != CCCC → transfer (1MB)
  Chunk 3: CCCC != DDDD → transfer (1MB)
  Total transferred: 4MB (the whole file!) even though only 1MB was new

With content-defined chunking (CDC):
  CDC finds natural boundaries; AAAA, BBBB, CCCC, DDDD are still the same chunks
  Only XXXX is new → transfer 1MB
  Total transferred: 1MB (25% of the file)
```

## 24.2 FastCDC Algorithm (Content-Defined Chunking)

FastCDC is the state-of-the-art CDC algorithm (Wen Xia et al., USENIX ATC 2016).
It achieves ~10 GB/s throughput while producing chunk boundaries that are stable
across insertions and deletions:

```rust
use fastcdc::v2020::{FastCDC, StreamCDC};

pub struct ContentDefinedChunker {
    min_size: u32,   // 512 KB default
    avg_size: u32,   // 2 MB default  
    max_size: u32,   // 8 MB default
}

impl ContentDefinedChunker {
    pub fn chunks<'a>(&self, data: &'a [u8]) -> impl Iterator<Item = &'a [u8]> {
        FastCDC::new(data, self.min_size, self.avg_size, self.max_size)
            .map(|chunk| &data[chunk.offset..chunk.offset + chunk.length])
    }
    
    pub async fn chunks_from_file(
        &self,
        path: &Path,
    ) -> impl Stream<Item = ChunkResult> {
        // Streaming CDC: never loads full file into memory
        let file = File::open(path).await?;
        StreamCDC::new(file, self.min_size, self.avg_size, self.max_size)
    }
}
```

## 24.3 Rabin Fingerprinting (Alternative to Gear Hash)

FastCDC uses Gear hash for chunk boundary detection. For compatibility with rsync-style
tools, also support Rabin fingerprinting:

```
Rabin fingerprint window: 48 bytes (rolling)
Chunk boundary: fingerprint % avg_size == MAGIC_VALUE

Rabin vs Gear hash:
  Gear hash: ~2x faster (SIMD-friendly), weaker statistical properties
  Rabin:     ~0.5x speed, stronger independence, used by LBFS/rsync
  Recommendation: Gear hash (FastCDC) as default; Rabin for rsync interop
```

## 24.4 Full Delta Transfer Protocol

```
DELTA TRANSFER FLOW:

Sender:
  1. Propose delta: TransferOfferDelta { transfer_id, file_hash, cdc_params }
  2. Receiver: compute CDC chunks of local version, send DeltaBlockList
  3. Sender: diff own CDC chunks vs receiver's block list
  4. Send only: new chunks + instructions (keep, insert)

Wire:
  DeltaBlockList {
      transfer_id: Uuid,
      chunks: Vec<DeltaBlock>,
  }
  
  DeltaBlock {
      hash: [u8; 32],       // BLAKE3 of this CDC chunk
      length: u32,           // byte length of chunk
  }
  
  DeltaInstruction {
      transfer_id: Uuid,
      instructions: Vec<DeltaOp>,
  }
  
  enum DeltaOp {
      Keep { chunk_hash: [u8; 32] },   // receiver already has this
      Insert { data: Bytes },          // new chunk to write here
  }

Receiver reconstruction:
  Walk instructions in order:
    Keep: copy existing CDC chunk (already on disk)
    Insert: write new chunk data

Performance: if 90% of file unchanged → 90% bandwidth savings
```

## 24.5 cdc crate integration

```toml
# Cargo.toml addition for delta transfer (v2 preparation, feature-gated)
[features]
delta-transfer = ["fastcdc"]

[dependencies]
fastcdc = { version = "3.1", optional = true }
```

---

# PART 25: MERKLE FOREST FOR DIRECTORIES

## 25.1 Directory-Wide Verification Tree

Current plan: each file gets its own BLAKE3 root. For directory transfers,
build a Merkle Forest where each file is a leaf in a directory-level tree:

```
Directory transfer "project/":
  ┌─── DirMerkleTree root: BLAKE3([file_hashes sorted by path])
  │
  ├── src/main.rs     → BLAKE3 root (file-level Merkle tree)
  ├── src/lib.rs      → BLAKE3 root
  ├── Cargo.toml      → BLAKE3 root
  └── README.md       → BLAKE3 root

Wire: TransferOffer for a directory includes dir_merkle_root: [u8; 32]
  The receiver can verify individual files without receiving the whole directory.
  
Use case: "Did my ~/Documents transfer correctly?"
  arc verify ~/Documents --hash <dir_root>
  → Checks each file against directory Merkle tree; reports any mismatch
```

## 25.2 Incremental Directory Sync (v2 Design)

The directory Merkle tree enables efficient sync without transferring unchanged files:

```
Sync protocol:
  1. Sender sends: DirMerkleRoot { root, file_count, total_size }
  2. Receiver compares own directory's Merkle tree
  3. Receiver sends: DirDiff { files_missing: Vec<PathHash>, files_changed: Vec<PathHash> }
  4. Sender transfers only missing/changed files
  
This is how Syncthing, Git, and rsync work internally.
Arc v2 can support this without changing the core transfer engine.
```

---

# PART 26: MEMORY MANAGEMENT AND I/O ARCHITECTURE

## 26.1 Zero-Copy I/O Pipeline

The goal: file bytes should travel from disk to network without any CPU copies.

```
COPY-FREE PATH (Linux with io_uring + GSO):

  Storage → Page Cache (kernel)
               │
               │ io_uring sendmsg (zero-copy)
               ▼
  QUIC packet buffer (kernel)
               │
               │ GSO batch send (single syscall for N packets)
               ▼
  NIC DMA buffer → Wire

CPU copies: 0 (kernel handles DMA directly from page cache)
Syscalls per 1000 chunks: O(1) with GSO batching
```

```
CURRENT PLAN (user-space mmap + write):

  Storage → Page Cache (mmap read) → User buffer (copy #1) → Encrypt buffer (copy #2)
  → QUIC buffer (copy #3) → Kernel send buffer (copy #4) → Wire
  
With memmap2: copy #1 eliminated (mmap avoids explicit read)
With sendmsg vectored I/O: copies #3+#4 combined
Practical: 2 copies (mmap page → encrypt output → QUIC send)
```

## 26.2 io_uring for Linux

For maximum throughput on Linux (server deployments, Raspberry Pi, high-speed LAN):

```rust
use tokio_uring::fs::File;

// io_uring based file read: zero-copy to registered buffers
pub async fn read_chunks_uring(
    path: &Path,
    chunk_size: usize,
    tx: Sender<Bytes>,
) -> io::Result<()> {
    let file = tokio_uring::fs::File::open(path).await?;
    let mut offset = 0u64;
    
    loop {
        // Register buffer with kernel — stays pinned for DMA
        let buf = vec![0u8; chunk_size];
        let (result, buf) = file.read_at(buf, offset).await;
        let n = result?;
        if n == 0 { break; }
        
        offset += n as u64;
        tx.send(Bytes::from(buf[..n].to_vec())).await?;
    }
    Ok(())
}
```

Gate this behind `#[cfg(target_os = "linux")]` and the `io-uring` feature flag.

## 26.3 Memory Pool for Chunk Buffers

Allocating and deallocating 8MB buffers per chunk is expensive at scale.
Use a pool of pre-allocated buffers:

```rust
pub struct ChunkBufferPool {
    /// Stack of available buffers
    pool: Mutex<Vec<Vec<u8>>>,
    chunk_size: usize,
    max_pool_size: usize,
}

impl ChunkBufferPool {
    pub fn acquire(&self) -> PooledBuffer {
        let mut pool = self.pool.lock().unwrap();
        let buf = pool.pop().unwrap_or_else(|| vec![0u8; self.chunk_size]);
        PooledBuffer { buf, pool: Arc::clone(&self.pool_arc) }
    }
}

/// RAII wrapper: returns buffer to pool on drop
pub struct PooledBuffer {
    buf: Vec<u8>,
    pool: Weak<ChunkBufferPool>,
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.upgrade() {
            pool.return_buffer(std::mem::take(&mut self.buf));
        }
    }
}
```

This eliminates allocator pressure during sustained transfers where thousands
of chunk buffers cycle rapidly.

---

# PART 27: STORAGE PIPELINE WITH BACKPRESSURE

## 27.1 Full Pipeline Architecture

```
┌────────────┐  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────┐
│ Disk Read  │→ │  Compress   │→ │   Encrypt    │→ │  Hash/Tree   │→ │  Queue   │→ Wire
│ (mmap/uring│  │ (zstd/lz4)  │  │ (ChaCha20   │  │ (BLAKE3      │  │ (QUIC    │
│ + read-    │  │ Adaptive    │  │  Poly1305)   │  │  Merkle leaf)│  │ streams) │
│ ahead)     │  │             │  │              │  │              │  │          │
└────────────┘  └─────────────┘  └──────────────┘  └──────────────┘  └──────────┘
     │                │                  │                  │               │
     └────────────────┴──────────────────┴──────────────────┘               │
                             Bounded channels (backpressure)                 │
                             capacity = 4 buffers per stage                  │
                             If full → upstream stage pauses → disk I/O      │
                             naturally rate-limits to network throughput ◄──┘
```

## 27.2 Backpressure Implementation

```rust
use tokio::sync::mpsc;

pub struct TransferPipeline {
    read_tx:     mpsc::Sender<RawChunk>,       // cap=4: read → compress
    compress_tx: mpsc::Sender<CompressedChunk>,// cap=4: compress → encrypt
    encrypt_tx:  mpsc::Sender<EncryptedChunk>, // cap=4: encrypt → hash
    hash_tx:     mpsc::Sender<HashedChunk>,    // cap=4: hash → queue
    queue_tx:    mpsc::Sender<HashedChunk>,    // cap=64: queue → QUIC
}

// Capacity=4 means at most 4 * chunk_size = 32MB RAM used per pipeline stage
// If QUIC send is slower than disk read: hash_tx fills → encrypt_tx stalls →
//   compress_tx stalls → read_tx stalls → disk I/O pauses
// This prevents OOM on large files and provides natural rate matching.
```

## 27.3 Read-Ahead Strategy

```rust
pub struct ReadAheadController {
    /// Number of chunks to read ahead of the network send position
    /// Adaptive: increases if disk is faster than network, decreases if memory pressure
    read_ahead_chunks: AtomicU32,
    
    /// Current memory budget for read-ahead buffers
    memory_budget_bytes: AtomicU64,
}

impl ReadAheadController {
    /// Adjust read-ahead based on runtime measurements
    pub fn adjust(&self, disk_throughput: u64, network_throughput: u64) {
        let ideal_ahead = (disk_throughput / network_throughput).max(1).min(32);
        self.read_ahead_chunks.store(ideal_ahead as u32, Ordering::Relaxed);
    }
}
```

---

# PART 28: BENCHMARK FRAMEWORK

## 28.1 Reproducible Benchmark Suite

```toml
# benches/Cargo.toml additions
[dev-dependencies]
criterion = { version = "0.5", features = ["async_tokio", "html_reports"] }
divan = "0.1"    # Alternative: faster to compile than criterion
```

```rust
// benches/full_suite.rs
criterion_group!(
    benches,
    bench_crypto_throughput,
    bench_transfer_throughput_by_size,
    bench_transfer_latency_loopback,
    bench_nat_traversal_success_rate,
    bench_compression_ratio_by_filetype,
    bench_cdc_chunking_speed,
    bench_blake3_parallel_hashing,
    bench_relay_concurrent_rooms,
    bench_reconnect_time,
    bench_resume_overhead,
);
```

## 28.2 Benchmark Metrics Matrix

```
Benchmark               │ What it measures                    │ Target
────────────────────────┼─────────────────────────────────────┼───────────────────
crypto_throughput        │ ChaCha20 + BLAKE3 MB/s              │ > 3 GB/s (1 core)
transfer_1mb_loopback   │ End-to-end latency for 1MB transfer  │ < 50ms
transfer_1gb_loopback   │ Throughput for 1GB transfer          │ > 2 GB/s
transfer_lan_10gbe      │ Throughput on 10GbE LAN             │ > 8 GB/s
transfer_wan_100mbps    │ Throughput on 100 Mbps WAN link     │ > 90 Mbps
transfer_5pct_loss      │ Throughput with 5% packet loss       │ > 40 Mbps
compression_text        │ Zstd ratio + speed on source code    │ > 5:1, > 1 GB/s
compression_video       │ Detection speed (should skip)        │ < 5ms to decide
cdc_chunking_speed      │ FastCDC throughput on 1GB file       │ > 5 GB/s
blake3_parallel_1gb     │ BLAKE3 on 1GB file (all cores)       │ < 1 second
reconnect_50pct         │ Time to resume from 50% complete     │ < 2 seconds
relay_1000_rooms        │ Relay memory under 1000 concurrent   │ < 100MB RSS
nat_traversal_success   │ % of direct connections in test lab  │ > 85%
```

## 28.3 Reproducibility Requirements

```bash
# All benchmarks run in isolated environment:
# - CPU frequency pinned: sudo cpupower frequency-set -f 2GHz
# - Network interface: loopback or dedicated test VLAN
# - Disk: tmpfs (eliminate disk I/O variance)
# - Memory: pre-allocated, no GC pressure

./scripts/bench.sh \
  --output benchmarks/$(git rev-parse --short HEAD).json \
  --compare benchmarks/baseline.json \
  --threshold 5%  # fail if any benchmark regresses > 5%

# CI gate: benchmarks run on every release tag, results committed to repo
```

---

# PART 29: FAULT INJECTION FRAMEWORK

## 29.1 Network Fault Injection

```rust
/// Network fault injector for testing resilience
pub struct FaultInjector {
    config: FaultConfig,
    rng: SmallRng,
}

pub struct FaultConfig {
    /// Probability of dropping each packet (0.0–1.0)
    packet_loss: f32,
    
    /// Maximum random delay added to each packet (milliseconds)
    max_delay_ms: u32,
    
    /// Probability of duplicating each packet
    duplication_rate: f32,
    
    /// Probability of reordering (holding packet until next arrives)
    reorder_rate: f32,
    
    /// Bandwidth cap (bytes/sec, 0 = unlimited)
    bandwidth_bps: u64,
    
    /// Whether to inject a connection drop after N bytes
    drop_after_bytes: Option<u64>,
    
    /// Whether to flip a random bit in every Nth packet (bit error simulation)
    corruption_every_n: Option<u32>,
}

impl FaultInjector {
    pub async fn wrap_connection(&self, conn: Connection) -> FaultyConnection {
        FaultyConnection { inner: conn, injector: self.clone() }
    }
}
```

## 29.2 Fault Scenarios (Must All Pass in CI)

```rust
// tests/fault_injection/

#[tokio::test]
async fn test_30pct_packet_loss() {
    let config = FaultConfig { packet_loss: 0.30, ..Default::default() };
    let result = transfer_with_faults(100 * MB, config).await;
    assert_eq!(blake3_hash(&result), expected_hash);
}

#[tokio::test]
async fn test_sudden_network_switch() {
    // Simulate WiFi → LTE switchover (IP change)
    let (mut sender, receiver) = spawn_pair().await;
    let file = create_temp_file(500 * MB);
    let transfer = tokio::spawn(sender.send_file(file));
    
    tokio::time::sleep(Duration::from_millis(500)).await;
    sender.simulate_ip_change().await;  // QUIC connection migration
    
    let received = transfer.await.unwrap();
    assert_eq!(blake3_hash(&received), expected_hash);
}

#[tokio::test]
async fn test_relay_crash_at_50pct() { ... }

#[tokio::test]
async fn test_disk_full_at_90pct() {
    // Mock filesystem reports full at 90% of file written
    let receiver = spawn_receiver_with_mock_fs(FsConfig {
        fail_write_after_bytes: 450 * MB,  // 90% of 500MB
    });
    let result = send_500mb().await;
    assert_eq!(result, Err(ArcError::DiskFull));
    // Verify temp file was cleaned up:
    assert!(!receiver.temp_dir_has_files());
}

#[tokio::test]
async fn test_clock_skew_30s() {
    // Receiver's clock is 30 seconds ahead
    // Session nonces and timestamps must still validate
    let receiver = spawn_receiver_with_clock_offset(30);
    let result = send_small_file().await;
    assert!(result.is_ok(), "30s clock skew should be tolerated");
}

#[tokio::test]
async fn test_bit_flip_in_chunk() {
    // Single bit flipped in chunk 42 of 100
    let injector = FaultConfig { corruption_every_n: Some(42), ..Default::default() };
    let result = transfer_with_faults(100 * MB, injector).await;
    // Should detect, request retransmit, and succeed:
    assert_eq!(blake3_hash(&result), expected_hash);
    // Verify a ChunkNak was sent for chunk 42:
    assert!(transfer_log.contains_event(Event::ChunkNak { index: 42 }));
}

#[tokio::test]
async fn test_relay_sends_3_member_count() {
    // Relay (under test) injects a false room_member_count = 3
    let relay = spawn_malicious_relay(MaliciousConfig {
        inject_member_count: Some(3),
    });
    let result = pair_and_transfer_via(&relay).await;
    assert_eq!(result, Err(ArcError::RelayCompromised));
}

#[tokio::test]
async fn test_burst_packet_loss() {
    // Simulates real-world WiFi bursty loss (not uniform)
    // tc netem loss 5% 25% = 5% base loss, 25% correlation = bursty
    let config = FaultConfig {
        packet_loss: 0.05,
        burst_correlation: 0.25,  // Gilbert-Elliott burst model
        ..Default::default()
    };
    let result = transfer_with_faults(1 * GB, config).await;
    assert_eq!(blake3_hash(&result), expected_hash);
}
```

---

# PART 30: PROTOCOL VERIFICATION AND FUZZING

## 30.1 State Machine Fuzzing

Beyond input fuzzing, fuzz the *state machine transitions*:

```rust
// fuzz/fuzz_targets/fuzz_state_machine.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Interpret input as a sequence of (state, message) pairs
    // Goal: find any (state, message) that causes panic or UB
    let mut session = Session::new_for_fuzzing();
    let mut cursor = data;
    
    while cursor.len() > 2 {
        let msg_type = cursor[0];
        let msg_len = u16::from_le_bytes([cursor[1], cursor[2]]) as usize;
        cursor = &cursor[3..];
        
        if cursor.len() < msg_len { break; }
        let msg_data = &cursor[..msg_len];
        cursor = &cursor[msg_len..];
        
        // This MUST NOT panic regardless of input:
        let _ = session.handle_raw_message(msg_type, msg_data);
    }
});
```

## 30.2 Differential Testing

Compare arc's behavior against a reference implementation:

```rust
// tests/differential/
// Run the same transfer in two configurations and compare results:
// Configuration A: QUIC direct
// Configuration B: TCP relay fallback
// Both MUST produce identical output files

#[tokio::test]
async fn differential_quic_vs_tcp_relay() {
    let file = create_deterministic_file(50 * MB, seed=42);
    
    let result_quic = transfer_via_quic_direct(file.clone()).await;
    let result_tcp  = transfer_via_tcp_relay(file.clone()).await;
    
    assert_eq!(blake3_hash(&result_quic), blake3_hash(&result_tcp));
}

// Also differential test: compression on vs off
// Same file → different transfer paths → same output
```

## 30.3 Coverage-Guided Fuzzing (AFL++ / cargo-fuzz)

```bash
# Fuzz targets to maintain:
fuzz/fuzz_targets/
  fuzz_protocol_deserialize.rs   # Throw random bytes at bincode parser
  fuzz_filename_sanitize.rs      # Random Unicode filenames
  fuzz_chunk_reassemble.rs       # Random chunk orderings and sizes  
  fuzz_pairing_handshake.rs      # Random bytes as peer messages
  fuzz_state_machine.rs          # Random (state, message) sequences
  fuzz_cdc_chunker.rs            # Random file contents → CDC boundaries
  fuzz_compression.rs            # Random data → compress → decompress
  fuzz_merkle_tree.rs            # Random chunks → tree → verify proofs

# CI: Run each fuzz target for 60 seconds on every PR
# Release: Run for 24 hours before each major version
```

## 30.4 Mutation Testing

Use `cargo-mutants` to verify test quality:

```bash
cargo mutants --package arc-core --test-workspace
# Measures: what % of code mutations are caught by tests
# Target: > 85% mutation kill rate for arc-core (crypto and protocol modules)
# Red flag: mutation score < 60% means tests aren't verifying behavior
```

---

# PART 31: PERFORMANCE ENGINEERING

## 31.1 SIMD Optimization Points

BLAKE3 already uses AVX2/AVX-512/NEON automatically via the `blake3` crate.
Additional SIMD opportunities:

```rust
// Filename sanitization (called for every filename in directory transfers)
// Can sanitize 16 chars at once with SSE2 range checks:
#[cfg(target_arch = "x86_64")]
unsafe fn sanitize_simd(input: &mut [u8; 16]) {
    use std::arch::x86_64::*;
    let v = _mm_loadu_si128(input.as_ptr() as *const __m128i);
    let control_mask = _mm_cmplt_epi8(v, _mm_set1_epi8(0x20));
    let escape_mask  = _mm_cmpeq_epi8(v, _mm_set1_epi8(0x1B));
    let bad = _mm_or_si128(control_mask, escape_mask);
    let replacement = _mm_set1_epi8(b'?' as i8);
    let result = _mm_blendv_epi8(v, replacement, bad);
    _mm_storeu_si128(input.as_mut_ptr() as *mut __m128i, result);
}

// CDC chunker (Gear hash): process 8 bytes per iteration with SIMD
// FastCDC crate already does this internally
```

## 31.2 NUMA Awareness (Server Deployments)

For the relay server running on multi-socket servers:

```rust
// Pin relay worker threads to NUMA nodes:
// Connections from one geographic region → workers on NUMA node 0
// Connections from another region → workers on NUMA node 1
// This prevents cross-NUMA memory bus traffic in high-throughput scenarios

#[cfg(target_os = "linux")]
fn pin_to_numa_node(node: u32) {
    use nix::sched::{sched_setaffinity, CpuSet};
    // Get CPUs on this NUMA node via /sys/devices/system/node/nodeN/cpulist
    let cpus = read_numa_cpus(node);
    let mut cpu_set = CpuSet::new();
    for cpu in cpus { cpu_set.set(cpu).unwrap(); }
    sched_setaffinity(Pid::from_raw(0), &cpu_set).unwrap();
}
```

## 31.3 Profiling Targets

```bash
# CPU profiling (find hot paths)
cargo install flamegraph
cargo flamegraph --bin arc -- send large_file.bin --to test-device

# Memory profiling (find allocations)
cargo install heaptrack
heaptrack target/release/arc send large_file.bin --to test-device
heaptrack_gui heaptrack.arc.*.gz

# Async task profiling (find blocked tasks)
# Add to arc-core:
tracing-subscriber with tokio-console feature
tokio-console (cargo install tokio-console)

# Cache miss profiling (find cache-unfriendly data structures)
perf stat -e cache-misses,cache-references target/release/arc send large_file.bin
```

## 31.4 Compile-Time Optimizations

```toml
# Cargo.toml release profile
[profile.release]
lto = "fat"              # Link-time optimization across all crates
codegen-units = 1        # Single codegen unit for maximum optimization
opt-level = 3            # Maximum optimization
strip = "debuginfo"      # Strip debug info (reduces binary size ~60%)
panic = "abort"          # Remove panic unwinding (saves ~5% binary size)

# For maximum performance on specific targets:
[profile.release-native]
inherits = "release"
target-cpu = "native"    # Use CPU-specific instructions (not portable)
# Used for self-built binaries; release binaries use x86-64-v2 baseline
```

---

# PART 32: MOBILE-SPECIFIC OPTIMIZATIONS

## 32.1 Battery Saver Mode

```rust
pub struct MobilePowerMode {
    pub is_battery_saver_active: bool,
    pub battery_level_pct: u8,
    pub is_charging: bool,
    pub is_on_wifi: bool,           // false = cellular (metered + battery drain)
}

pub fn transfer_config_for_power_mode(mode: &MobilePowerMode) -> TransferConfig {
    if mode.is_battery_saver_active || mode.battery_level_pct < 20 {
        TransferConfig {
            max_parallel_chunks: 2,    // reduce from 64 → 2 (saves CPU/radio)
            compression_level: 1,       // fastest compression (saves CPU)
            chunk_size_kb: 512,         // smaller chunks = more frequent pauses
            network_timeout_ms: 5000,   // more patient (radio may duty-cycle)
        }
    } else if !mode.is_on_wifi && !mode.is_charging {
        TransferConfig {
            max_parallel_chunks: 8,     // moderate: cellular is expensive
            compression_level: 3,       // good compression = less data = less battery
            chunk_size_kb: 1024,
            network_timeout_ms: 10000,  // cellular has higher latency variance
        }
    } else {
        TransferConfig::default()       // full speed on WiFi + charging
    }
}
```

## 32.2 Metered Network Detection

```swift
// iOS: detect if cellular connection is in use
import Network
let monitor = NWPathMonitor()
monitor.pathUpdateHandler = { path in
    if path.isExpensive {  // cellular, metered hotspot
        ArcTransferManager.shared.setNetworkMode(.metered)
    }
}

// Dart/Flutter: use connectivity_plus
ConnectivityResult.mobile → warn user about metered connection before large transfer
```

## 32.3 Thermal Throttling

```kotlin
// Android: detect thermal status
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
    powerManager.addThermalStatusListener { status ->
        when (status) {
            PowerManager.THERMAL_STATUS_MODERATE,
            PowerManager.THERMAL_STATUS_SEVERE -> {
                // Reduce parallel chunks to let CPU cool
                ArcEngine.setMaxParallelChunks(4)
            }
            PowerManager.THERMAL_STATUS_CRITICAL,
            PowerManager.THERMAL_STATUS_EMERGENCY -> {
                // Pause transfer to prevent damage
                ArcEngine.pauseAllTransfers()
                showToast("Transfer paused: device too hot")
            }
            else -> ArcEngine.setMaxParallelChunks(MAX_PARALLEL)
        }
    }
}
```

## 32.4 Wi-Fi Only Mode

```dart
// Flutter: gate large transfers on Wi-Fi check
Future<void> startTransfer(FileInfo file, String peerId) async {
    final connectivity = await Connectivity().checkConnectivity();
    final isWifiOnly = await PrefsService.getBool('wifi_only_transfers', true);
    
    if (isWifiOnly && connectivity != ConnectivityResult.wifi) {
        final confirmed = await showDialog(
            title: 'Cellular Transfer',
            body: '${file.sizeFormatted} will use mobile data. Continue?',
        );
        if (!confirmed) return;
    }
    
    await ArcBridge.sendFile(file.path, peerId);
}
```

---

# PART 33: RELAY SCALING AND OPERATIONS

## 33.1 Stateless Relay Architecture

All relay state must live in Redis (or equivalent) — no in-process state:

```rust
// Every relay instance is identical; load balancer can route any
// connection to any instance.

pub struct RelayRoom {
    room_id: [u8; 32],      // SHA256(nonce)
    members: Vec<MemberId>,  // max 2
    created_at: u64,
    expires_at: u64,         // created_at + 600s
}

// Redis key: "arc:room:{room_id_hex}"
// Redis TTL: 600 seconds (auto-expires)
// Redis cluster: 3-node, synchronous replication for consistency
```

## 33.2 Anycast Routing for Relay Discovery

```
arc client relay selection:
  1. Client queries DNS: relay.arc.sh → Anycast IP
  2. BGP anycast routes client to nearest relay PoP
  3. Relay PoP handles signaling
  4. Direct P2P connection: both clients use same PoP relay for signaling
     even if they ultimately hole-punch to each other directly

Geographic relay PoPs (target, using Fly.io or Cloudflare Workers):
  sin (Singapore)  → Asia-Pacific
  iad (Virginia)   → North America East  
  lax (Los Angeles)→ North America West
  ams (Amsterdam)  → Europe
  syd (Sydney)     → Oceania

Client relay discovery: measure RTT to each PoP on first run, cache result.
```

## 33.3 Relay Federation (Self-Hosting)

Allow organizations to run their own relay and federate with the default:

```toml
# arc config
[network]
relay_url = "wss://relay.arc.sh"           # default public relay
relay_fallbacks = [
    "wss://relay.corp.example.com",        # corporate relay (preferred for internal)
    "wss://relay2.arc.sh",                 # secondary public relay
]
relay_selection = "nearest"               # nearest | first_available | explicit
```

```
Federation protocol:
  If both peers are configured with the same corporate relay: use it
  If they have different relays: use default public relay
  Corporate relay can filter: only allow traffic from known device IDs
  This enables "enterprise mode" without cloud dependency
```

## 33.4 Relay Health and Graceful Draining

```rust
// arc-relay Kubernetes deployment with graceful drain:
// On SIGTERM: stop accepting new rooms, drain existing rooms, then exit
// Kubernetes readiness probe: /health returns 503 when draining
// Active rooms are migrated: relay sends { "type": "relay_migrate", "url": "..." }
// Client reconnects to new relay seamlessly

// Prometheus metrics for autoscaling:
arc_active_rooms_total         // HPA scale up at > 8000 rooms (cap = 10000)
arc_relay_bytes_per_second     // HPA scale up at > 8 Gbps
arc_relay_cpu_percent          // HPA scale up at > 70%
arc_relay_p99_latency_ms       // Alert if > 100ms
```

---

# PART 34: PLUGIN AND EXTENSION ARCHITECTURE

## 34.1 Extension Points

Arc's architecture should define explicit extension boundaries, each an async trait:

```rust
/// Storage backend: where received files go
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Called before transfer starts; returns writable sink
    async fn open_for_write(
        &self,
        transfer: &TransferInfo,
    ) -> Result<Box<dyn AsyncWrite + Unpin + Send>>;
    
    /// Called on completion; atomically commits the transfer
    async fn commit(&self, transfer: &TransferInfo) -> Result<PathBuf>;
    
    /// Called on failure; cleans up partial state
    async fn rollback(&self, transfer: &TransferInfo) -> Result<()>;
}

// Built-in implementations:
//   LocalFilesystem    → current behavior (default)
//   Encrypted vault    → additional layer of at-rest encryption (v2)
//   S3 / object store  → for server-mode deployments

/// Transport backend: how bytes get from A to B
#[async_trait]
pub trait TransportBackend: Send + Sync {
    async fn connect(&self, peer: &PeerAddress) -> Result<Box<dyn Connection>>;
    async fn listen(&self) -> Result<Box<dyn ConnectionListener>>;
    fn name(&self) -> &str;
    fn priority(&self) -> u32;  // higher = tried first
}

// Built-in implementations (in order of priority):
//   QuicLan         → mDNS discovery → direct QUIC (priority 100)
//   QuicHolePunch   → STUN/iroh → P2P QUIC (priority 80)
//   TcpRelay        → relay → TCP bridge (priority 40)
//   WssRelay        → relay → WebSocket (priority 20)

/// Compression backend: pluggable algorithms
#[async_trait]
pub trait CompressionBackend: Send + Sync {
    fn capability_type(&self) -> CapabilityType;
    fn compress(&self, data: &[u8], level: u8) -> Result<Vec<u8>>;
    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn estimate_ratio(&self, sample: &[u8]) -> f32;  // > 1.0 = compressible
}

/// Authentication backend: how devices verify each other
#[async_trait]
pub trait AuthBackend: Send + Sync {
    async fn verify_peer(&self, peer_id: &DeviceId, challenge: &[u8]) -> Result<bool>;
    async fn sign_challenge(&self, challenge: &[u8]) -> Result<Vec<u8>>;
    fn device_id(&self) -> &DeviceId;
}

// Built-in: Ed25519PairingKey (default)
// Future: OIDCToken, CertificateChain, HardwareKey (YubiKey)
```

## 34.2 Plugin Discovery

```toml
# ~/.config/arc/plugins.toml
[[plugins]]
name = "arc-s3-backend"
path = "/usr/local/lib/arc/plugins/arc_s3_backend.so"
type = "storage"

[[plugins]]
name = "arc-tor-transport"
path = "/usr/local/lib/arc/plugins/arc_tor.so"
type = "transport"
```

```rust
// Plugin API (dynamic loading via libloading)
// Plugins export:
pub extern "C" fn arc_plugin_init() -> *mut dyn StorageBackend;
pub extern "C" fn arc_plugin_version() -> u32;  // must match ARC_PLUGIN_ABI

// Safety: plugins run in same process — document that plugins must be trusted code
```

---

# PART 35: ENTERPRISE FEATURES (FUTURE — v3+)

Documented here for architectural decisions that must not be closed off in v1:

## 35.1 Device Approval Workflow

```
Organizational arc deployment:
  - Admin registers approved device IDs in policy server
  - arc daemon checks policy before accepting transfer from new device
  - Policy server: simple REST API { "device_id": "...", "approved": true/false }
  - Policy URL configured: arc config set policy_url https://policy.corp.example.com
```

## 35.2 Audit Logging

```
Events to log (structured JSON, append-only):
  device_connected    { device_id, timestamp, ip, path_type }
  transfer_started    { transfer_id, device_id, file_count, total_bytes, direction }
  transfer_completed  { transfer_id, duration_ms, bytes_actual }
  transfer_aborted    { transfer_id, reason }
  pairing_completed   { device_id, device_name, timestamp }
  device_revoked      { device_id, timestamp, revoked_by }

Log stored: ~/.local/share/arc/audit.log (JSON Lines)
Format: { "event": "transfer_completed", "ts": "2026-06-26T12:00:00Z", ... }
Retention: configurable (default: 90 days)
Export: arc audit export --since 2026-01-01 --format json
```

## 35.3 Policy Engine (v3)

```
Rules engine for organizational deployments:
  - "Only allow transfers to devices in same org domain"
  - "Block transfers > 1GB without manager approval"
  - "Require fingerprint verification for all pairings"
  - "Block clipboard sync on devices in 'restricted' group"

Expressed as: YAML rules evaluated against transfer metadata
Goal: arc can be deployed in regulated environments (healthcare, finance)
      without requiring a commercial license
```

---

# PART 36: UPDATED DEPENDENCY LIST (COMPLETE)

```toml
[dependencies]
# === Async Runtime ===
tokio = { version = "1.40", features = ["full"] }

# === Transport (Option A: iroh recommended) ===
iroh       = "1.0"
iroh-blobs = "0.35"

# === Transport (Option B: custom, fallback) ===
quinn      = "0.11"
rustls     = "0.23"
rcgen      = "0.13"

# === Crypto ===
x25519-dalek      = "2.0"
ed25519-dalek     = "2.0"
hkdf              = "0.12"
chacha20poly1305  = "0.10"
aes-gcm           = "0.10"          # AES-256-GCM for AES-NI fast path
blake3            = { version = "1.5", features = ["rayon"] }
rand              = "0.8"

# === Post-Quantum (feature-gated) ===
[features]
pqc = ["pqcrypto-mlkem", "pqcrypto-mldsa"]

[dependencies.pqcrypto-mlkem]
version  = "0.3"
optional = true

[dependencies.pqcrypto-mldsa]
version  = "0.3"
optional = true

# === Compression ===
zstd      = "0.13"
lz4_flex  = "0.11"

# === Content-Defined Chunking (feature-gated) ===
[dependencies.fastcdc]
version  = "3.1"
optional = true

# === I/O ===
memmap2   = "0.9"
bytes     = "1"

[target.'cfg(target_os = "linux")'.dependencies]
tokio-uring = "0.5"               # io_uring support

# === Protocol ===
serde    = { version = "1", features = ["derive"] }
bincode  = "2.0"                   # BREAKING: upgraded from 1.3
uuid     = { version = "1", features = ["v4"] }
bitflags = "2"

# === Discovery ===
mdns-sd      = "0.11"
stunclient   = "0.2"

# === CLI ===
clap         = { version = "4", features = ["derive"] }
indicatif    = "0.17"
crossterm    = "0.27"
qrcode       = "0.14"

# === Clipboard ===
arboard      = "3"

# === Relay ===
axum         = { version = "0.7", features = ["ws"] }
tower        = "0.4"
tokio-tungstenite = "0.23"

# === Storage ===
sqlx         = { version = "0.8", features = ["sqlite", "runtime-tokio"] }

# === Observability ===
tracing             = "0.1"
tracing-subscriber  = { version = "0.3", features = ["json"] }
prometheus          = "0.13"

[dev-dependencies]
criterion    = { version = "0.5", features = ["async_tokio", "html_reports"] }
proptest     = "1.4"
tokio-test   = "0.4"
```

---

# PART 37: FINAL ARCHITECTURE SUMMARY (UPDATED)

```
arc — Complete Architecture (v1.0 + roadmap)

┌─────────────────────────────────────────────────────────────────┐
│                    arc-core (Rust library)                       │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  Discovery   │  │  Transport   │  │   Transfer Engine    │  │
│  │              │  │  (iroh 1.0   │  │                      │  │
│  │ mDNS (LAN)   │  │  or custom   │  │ FastCDC chunker      │  │
│  │ STUN probe   │  │  quinn)      │  │ BLAKE3 Merkle tree   │  │
│  │ Relay signal │  │              │  │ Adaptive compression │  │
│  │ IPv6 HE      │  │ BBRv3 CC     │  │ Delta transfer (v2)  │  │
│  └──────────────┘  │ Multipath    │  │ Sparse file support  │  │
│                    │ Connection   │  │ Hard link dedup      │  │
│  ┌──────────────┐  │ migration    │  └──────────────────────┘  │
│  │    Crypto    │  └──────────────┘                            │
│  │              │  ┌──────────────┐  ┌──────────────────────┐  │
│  │ Suite negot. │  │  Scheduler   │  │   State Machine      │  │
│  │ X25519+MLKEM │  │  Priority WFQ│  │   Formal FSM         │  │
│  │ ChaCha20/AES │  │  Backpressure│  │   INV-1 thru INV-10  │  │
│  │ Ed25519+MLDS │  │  pipeline    │  │   Timeout budget     │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   Protocol   │  │  Metadata    │  │   Plugin API         │  │
│  │  TLV capab.  │  │  Privacy     │  │  StorageBackend      │  │
│  │  Suite negot.│  │  Padding     │  │  TransportBackend    │  │
│  │  Versioned   │  │  Cover traf. │  │  CompressionBackend  │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
         │                          │
         ▼                          ▼
┌──────────────────┐      ┌──────────────────────┐
│    arc-cli       │      │  arc-mobile (Flutter) │
│                  │      │  Rust HTTP (rhttp)    │
│ + arc queue      │      │ + Battery saver mode  │
│ + arc verify     │      │ + Thermal throttle    │
│ + arc panic      │      │ + Metered network det │
│ + arc completions│      │ + BGProcessingTask    │
│ + --json mode    │      │ + WorkManager         │
└──────────────────┘      └──────────────────────┘
         │
         ▼
┌──────────────────┐
│    arc-relay     │
│                  │
│ Stateless        │
│ Redis-backed     │
│ Geo-distributed  │
│ Anycast routing  │
│ Federation API   │
│ Graceful drain   │
│ PoW for rooms    │
└──────────────────┘
```

---

*Complete scope: ~8,000 lines of core Rust, ~2,000 lines Flutter, ~800 lines relay, ~1,500 lines tests/benchmarks/fuzz.*
*14–16 weeks part-time / 8–9 weeks full-time.*
*This document combines the original plan, competitive analysis, and all extensions into a single engineering specification.*
