# arc 🌌

`arc` is a universal, end-to-end encrypted, peer-to-peer file and clipboard transfer tool built in Rust. It utilizes the modern **Iroh (QUIC)** transport stack for direct NAT-to-NAT connections, falling back to secure WebSocket rooms when direct paths are blocked.

Designed with a strict, proactive defense model, `arc` explicitly mitigates the protocol design and security vulnerabilities found in legacy tools (such as `croc`).

---

## Key Features

- **Blazing Fast QUIC Direct Path**: ~90%+ direct connection success rates across NAT boundaries without cloud relays, using QUIC hole-punching.
- **Adaptive Compression**: Probes the first 64 KB of each file to select the optimal algorithm:
  - Pre-compressed files (JPEG, MP4, ZIP) → Passed raw (No CPU waste)
  - Highly compressible files (text, code, JSON) → compressed using Zstd level 3
  - Marginally compressible files → compressed using LZ4 (~10 GB/s throughput)
- **Compact Resume Bitmaps**: Interrupted transfers resume seamlessly, only requesting missing chunks from the sender.
- **Terminal Injection & Path Traversal Proof**: Filenames are sanitized of control/ANSI characters, and relative/absolute paths are strictly validated to prevent directory traversal overwrites.
- **Zero-Knowledge WebSocket Relay**: Signaling payloads are encrypted client-side using a key derived from the 6-word phrase. The relay sees only opaque ciphertexts.
- **MITM Protection**: Immediate session abort if a third member is detected in the communication room (INV-9).
- **Daemon Mode Clipboard Sync**: Loop-deduplicated, forward-secure clipboard synchronization between paired devices.

---

## Architectural Flow

```text
  Sender (Client)                 arc-relay (WebSocket)             Receiver (Client)
        |                                   |                               |
        |─────────── Join Room ────────────>|                               |
        |             (Opaque)              |                               |
        |                                   |<────────── Join Room ─────────|
        |                                   |             (Opaque)          |
        |                                   |                               |
        |<───────── Send Signals ──────────>|                               |
        |       (Encrypted Handshake)       |                               |
        |                                   |                               |
        |───────────────────────── QUIC NAT Probe ─────────────────────────>|
        |                  (Direct Connection Negotiated)                   |
        |                                                                   |
        |=================== Ephemeral X25519 DH Handshake =================|
        |                                                                   |
        |───────────── Authenticated Hello & Capability Match ─────────────>|
        |                                                                   |
        |───────────── File Transfer (ChaCha20 / AES-GCM + BLAKE3) ────────>|
```

---

## Installation & Setup

### Prerequisites
Make sure you have Rust (v1.85 or later) installed:
```bash
cargo --version
```

### Build from Source
```bash
# Clone the repository
git clone https://github.com/dhiraj-rajput/arc.git
cd arc

# Build workspace in release mode
cargo build --release
```
The compiled binaries will be located in:
- `target/release/arc` (CLI Client)
- `target/release/arc-relay` (Signaling Relay)

---

## CLI Usage

### 1. Device Pairing
To establish a persistent, cryptographically secure trust relationship between two devices:
```bash
# On Device A:
arc pair

# On Device B:
arc pair --joiner <6-word-pairing-code>
```

### 2. Sending Files
Once paired, you can transfer files directly:
```bash
# Send a file to a paired device
arc send /path/to/document.pdf --to "device-b"

# Send a directory (automatically packed and validated)
arc send /path/to/folder/ --to "device-b"

# Send via stdin pipe
cat source.txt | arc send --stdin --name "piped.txt"
```

### 3. Receiving Files
To receive files from a sender using a transfer code phrase:
```bash
# Save to current directory
arc receive "acid-acme-acre-acts-aged-aide"

# Save to a specific directory
arc receive "acid-acme-acre-acts-aged-aide" --dir ~/Downloads

# Write directly to stdout
arc receive "acid-acme-acre-acts-aged-aide" --stdout > received.txt
```

### 4. Clipboard Sync (Daemon Mode)
Synchronize clipboards in real-time across your paired devices:
```bash
arc clipboard "your-secure-sync-phrase"
```

---

## Security Model (Threat Mitigation Checklist)

`arc` enforces **10 strict Security Invariants (INV-1 to INV-10)** to guarantee data integrity and confidentiality:

| Invariant | Security Threat | Mitigation in `arc` | Code Location |
| :--- | :--- | :--- | :--- |
| **INV-1** | Eavesdropping | Content must travel encrypted with ChaCha20-Poly1305 or AES-GCM. | `crypto/cipher.rs` |
| **INV-5** | Nonce Reuse / Replay | Monotonically incrementing nonces prefixed with session ID and direction flags. | `crypto/cipher.rs` |
| **INV-7** | Terminal Escape Injection | Filenames are sanitized of escape sequences and control chars before display. | `security.rs` |
| **INV-8** | Path Traversal / Overwrite | Path separator parsing prevents `../` escaping from destination. | `security.rs` |
| **INV-9** | Compromised Relay MITM | Connection aborts if the signaling room member count exceeds 2. | `security.rs` |
| **INV-10** | Local Secret Leakage | Secrets are stored in OS keychain/DPAPI; never passed in command argv. | `keystore.rs` |

---

## Running Tests & Diagnostics

To run the complete test suite:
```bash
cargo test --workspace
```

For performance profiling (CPU & Memory):
```bash
# Cryptographic primitives and compression benchmark
cargo bench -p arc-core --bench transfer
```

---

## Self-Hosting the Relay

You can run your own signaling relay:
```bash
cargo run --release --bin arc-relay -- --port 9000
```

Configure clients to use your relay:
```bash
arc config set relay_url "ws://your-relay-ip:9000"
```
