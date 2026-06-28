//! All wire protocol message types for arc.
//!
//! Messages are serialized with `bincode 2.0` (breaking API change from 1.3).
//! Use `bincode::encode_to_vec` / `bincode::decode_from_slice`.
//!
//! # Session Flow
//!
//! ```text
//! Sender          Relay / Network         Receiver
//!   |─── Hello ──────────────────────────────►|
//!   |◄── HelloAck ───────────────────────────|
//!   |─── AuthChallenge ───────────────────────►|
//!   |◄── AuthResponse ────────────────────────|
//!   |─── AuthOk ──────────────────────────────►|
//!   |─── TransferOffer ───────────────────────►|
//!   |◄── TransferAccept ──────────────────────|
//!   |─── [Chunk × N] ─────────────────────────►|
//!   |◄── [ChunkAck × N] ─────────────────────|
//!   |─── TransferComplete ────────────────────►|
//!   |◄── TransferComplete ────────────────────|
//!   |─── Goodbye ─────────────────────────────►|
//! ```

use crate::compression::CompressionAlgo;
use crate::protocol::capability::CapabilityTLV;
use bincode::{Decode, Encode};

/// The kind of transfer being offered.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum TransferKind {
    /// A single regular file.
    File,
    /// A directory tree.
    Directory,
    /// Clipboard content (text or binary).
    Clipboard,
    /// Stdin stream (piped data with no known size).
    Stdin,
}

/// Reason for transfer abort.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum AbortReason {
    UserCancelled,
    DiskFull,
    HashMismatch,
    Timeout,
    RelayTampered,
    ProtocolError(String),
    IoError(String),
}

/// Reason for authentication failure.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum AuthFailReason {
    BadSignature,
    UnknownDevice,
    VersionMismatch,
    Timeout,
    NoCommonSuite,
    DeviceNotPaired,
    ProtocolError,
}

/// A single block descriptor in a delta transfer block list.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct DeltaBlock {
    /// BLAKE3 hash of this CDC chunk.
    pub hash: [u8; 32],
    /// Byte length of chunk.
    pub length: u32,
}

/// A single delta instruction operation.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum DeltaOp {
    /// The receiver already has this chunk, refer to it by its hash.
    Keep { chunk_hash: [u8; 32] },
    /// A new chunk of data to insert.
    Insert { data: Vec<u8> },
}

/// All arc protocol messages.
///
/// Serialized with bincode 2.0. All variants must derive `Encode + Decode`.
#[derive(Debug, Clone, Encode, Decode)]
pub enum ArcMessage {
    // ─── Handshake ───────────────────────────────────────────────────────────

    /// Session initiation. First message sent on a new connection.
    Hello {
        /// Wire format version. Current: 1.
        protocol_version: u16,
        /// Sender's 32-byte Ed25519 public key (device identity).
        device_id: [u8; 32],
        /// Random 32-byte nonce for HKDF session key derivation.
        nonce: [u8; 32],
        /// TLV-encoded capability list (what this device supports).
        capabilities: Vec<CapabilityTLV>,
    },

    /// Response to Hello. Sent by the peer who received Hello.
    HelloAck {
        protocol_version: u16,
        device_id: [u8; 32],
        nonce: [u8; 32],
        /// The capability intersection (subset of both sides' capabilities).
        selected_capabilities: Vec<CapabilityTLV>,
    },

    // ─── Authentication ──────────────────────────────────────────────────────

    /// Challenge sent after HelloAck. Peer must sign this with their Ed25519 key.
    AuthChallenge {
        /// 32 random bytes the peer must sign.
        challenge: [u8; 32],
    },

    /// Response to AuthChallenge. Contains the Ed25519 signature.
    AuthResponse {
        /// Ed25519 signature of the AuthChallenge bytes.
        signature: [u8; 64],
    },

    /// Authentication succeeded.
    AuthOk,

    /// Authentication failed.
    AuthFail {
        reason: AuthFailReason,
    },

    // ─── Transfer Negotiation ────────────────────────────────────────────────

    /// Offer to send a file or directory.
    TransferOffer {
        transfer_id: [u8; 16], // UUID bytes
        kind: TransferKind,
        /// Safe display name (must be sanitized by sender before sending).
        file_name: String,
        /// Total uncompressed size in bytes.
        total_size: u64,
        /// Number of chunks.
        chunk_count: u32,
        /// Chunk size in bytes (for all chunks except the last).
        chunk_size: u32,
        /// BLAKE3 Merkle root hash of the entire file.
        file_hash: [u8; 32],
        /// Fast sampling hash (BLAKE3 of first+last 128KB). For dedup probing.
        partial_hash: [u8; 32],
        /// Compression algorithm to be used (negotiated from capabilities).
        compression: CompressionAlgo,
    },

    /// Receiver accepts the transfer offer.
    TransferAccept {
        transfer_id: [u8; 16],
        /// Bitmap of chunks receiver already has (for resume). None = start fresh.
        resume_bitmap: Option<Vec<u8>>,
    },

    /// Receiver rejects the transfer offer.
    TransferReject {
        transfer_id: [u8; 16],
        reason: String,
    },

    // ─── Data Transfer ───────────────────────────────────────────────────────

    /// A single encrypted chunk of file data.
    ///
    /// `data` is the ChaCha20-Poly1305 (or AES-GCM) ciphertext.
    /// The nonce is deterministic: built from session_id + chunk_index.
    Chunk {
        transfer_id: [u8; 16],
        /// Zero-based chunk index.
        index: u32,
        /// BLAKE3 hash of the *original* (pre-compression) chunk data.
        hash: [u8; 32],
        /// Compressed + encrypted chunk data.
        data: Vec<u8>,
        /// Whether this is the last chunk in the transfer.
        is_last: bool,
    },

    /// Receiver acknowledges a chunk.
    ChunkAck {
        transfer_id: [u8; 16],
        index: u32,
    },

    /// Receiver rejects a chunk (hash mismatch or decrypt failure).
    /// Sender should retransmit the chunk.
    ChunkNak {
        transfer_id: [u8; 16],
        index: u32,
        /// Retry count from the receiver's perspective.
        retry_count: u8,
    },

    // ─── Delta Transfer (v2) ──────────────────────────────────────────────────

    /// Sent by receiver to request only differences for an existing file.
    DeltaBlockList {
        transfer_id: [u8; 16],
        chunks: Vec<DeltaBlock>,
    },

    /// Sent by sender containing instructions to reconstruct the file.
    DeltaInstruction {
        transfer_id: [u8; 16],
        instructions: Vec<DeltaOp>,
    },

    // ─── Transfer Completion ─────────────────────────────────────────────────

    /// All chunks have been sent. Receiver should verify the BLAKE3 root.
    TransferComplete {
        transfer_id: [u8; 16],
        /// Final BLAKE3 Merkle root (for whole-file verification).
        file_hash: [u8; 32],
        /// Duration of the transfer in milliseconds (sender-measured).
        duration_ms: u64,
        /// Bytes sent on the wire (may be less than total_size with compression).
        wire_bytes: u64,
    },

    /// Transfer aborted by either party.
    TransferAbort {
        transfer_id: [u8; 16],
        reason: AbortReason,
    },

    // ─── Relay Signaling ─────────────────────────────────────────────────────

    /// Relay → client: current member count in the room.
    ///
    /// INV-9: If count > 2, abort immediately (relay MITM detected).
    RoomMemberCount {
        count: u8,
    },

    // ─── File Metadata ───────────────────────────────────────────────────────

    /// Extended file metadata (sent after TransferAccept, before first Chunk).
    FileMetadata {
        transfer_id: [u8; 16],
        /// Unix timestamp of file creation (seconds since epoch).
        created_at: u64,
        /// Unix timestamp of last modification.
        modified_at: u64,
        /// Unix permissions (rwxrwxrwx as u32). None on Windows.
        unix_permissions: Option<u32>,
        /// Whether the file should be marked executable.
        is_executable: bool,
    },

    // ─── Keep-Alive ──────────────────────────────────────────────────────────

    /// Keep-alive ping. Must be responded to with Pong within 15 seconds.
    Ping {
        /// Monotonic timestamp from sender (milliseconds).
        timestamp_ms: u64,
    },

    /// Response to Ping.
    Pong {
        /// Echo the sender's timestamp for RTT measurement.
        timestamp_ms: u64,
    },

    // ─── Session Control ─────────────────────────────────────────────────────

    /// Graceful session termination.
    Goodbye {
        /// Human-readable reason (for logging).
        reason: Option<String>,
    },
}

pub const CONTROL_PADDED_SIZE: usize = 512;

/// Pad a serialized control message to a fixed size of 512 bytes.
/// The last 2 bytes store the total padding length as a u16 LE.
pub fn pad_control_message(msg: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    if msg.len() > CONTROL_PADDED_SIZE - 2 {
        return Err(anyhow::anyhow!("Control message too large for padding: {} bytes", msg.len()));
    }
    let mut padded = msg.to_vec();
    let pad_len = CONTROL_PADDED_SIZE - msg.len();
    if pad_len > 2 {
        let mut random_padding = vec![0u8; pad_len - 2];
        for byte in &mut random_padding {
            *byte = rand::random();
        }
        padded.extend(random_padding);
    }
    padded.extend(&(pad_len as u16).to_le_bytes());
    Ok(padded)
}

/// Strip the fixed padding from a 512-byte control message.
pub fn strip_control_padding(padded: &[u8]) -> Result<&[u8], anyhow::Error> {
    if padded.len() != CONTROL_PADDED_SIZE {
        return Err(anyhow::anyhow!("Invalid padded control message size: {} bytes (expected {})", padded.len(), CONTROL_PADDED_SIZE));
    }
    let pad_len_bytes = &padded[CONTROL_PADDED_SIZE - 2..];
    let pad_len = u16::from_le_bytes(pad_len_bytes.try_into().unwrap()) as usize;
    if !(2..=CONTROL_PADDED_SIZE).contains(&pad_len) {
        return Err(anyhow::anyhow!("Invalid control message padding length: {}", pad_len));
    }
    Ok(&padded[..CONTROL_PADDED_SIZE - pad_len])
}

impl ArcMessage {
    /// Returns a short string name for this message type (for logging / protocol errors).
    ///
    /// # INV-10: This must NEVER include secret values in its output.
    pub fn type_name(&self) -> &'static str {
        match self {
            ArcMessage::Hello { .. } => "Hello",
            ArcMessage::HelloAck { .. } => "HelloAck",
            ArcMessage::AuthChallenge { .. } => "AuthChallenge",
            ArcMessage::AuthResponse { .. } => "AuthResponse",
            ArcMessage::AuthOk => "AuthOk",
            ArcMessage::AuthFail { .. } => "AuthFail",
            ArcMessage::TransferOffer { .. } => "TransferOffer",
            ArcMessage::TransferAccept { .. } => "TransferAccept",
            ArcMessage::TransferReject { .. } => "TransferReject",
            ArcMessage::Chunk { .. } => "Chunk",
            ArcMessage::ChunkAck { .. } => "ChunkAck",
            ArcMessage::ChunkNak { .. } => "ChunkNak",
            ArcMessage::DeltaBlockList { .. } => "DeltaBlockList",
            ArcMessage::DeltaInstruction { .. } => "DeltaInstruction",
            ArcMessage::TransferComplete { .. } => "TransferComplete",
            ArcMessage::TransferAbort { .. } => "TransferAbort",
            ArcMessage::RoomMemberCount { .. } => "RoomMemberCount",
            ArcMessage::FileMetadata { .. } => "FileMetadata",
            ArcMessage::Ping { .. } => "Ping",
            ArcMessage::Pong { .. } => "Pong",
            ArcMessage::Goodbye { .. } => "Goodbye",
        }
    }

    /// Encode this message to bytes using bincode 2.0 with a 10MB limit.
    pub fn encode(&self) -> Result<Vec<u8>, bincode::error::EncodeError> {
        bincode::encode_to_vec(self, bincode::config::standard().with_limit::<10485760>())
    }

    /// Decode a message from bytes using bincode 2.0 with a 10MB limit.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), bincode::error::DecodeError> {
        bincode::decode_from_slice(bytes, bincode::config::standard().with_limit::<10485760>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg: ArcMessage) -> ArcMessage {
        let encoded = msg.encode().expect("encode must succeed");
        let (decoded, _) = ArcMessage::decode(&encoded).expect("decode must succeed");
        decoded
    }

    #[test]
    fn test_hello_roundtrip() {
        let msg = ArcMessage::Hello {
            protocol_version: 1,
            device_id: [0xAB; 32],
            nonce: [0xCD; 32],
            capabilities: vec![],
        };
        let back = roundtrip(msg);
        assert!(matches!(back, ArcMessage::Hello { protocol_version: 1, .. }));
    }

    #[test]
    fn test_auth_ok_roundtrip() {
        let back = roundtrip(ArcMessage::AuthOk);
        assert!(matches!(back, ArcMessage::AuthOk));
    }

    #[test]
    fn test_chunk_roundtrip() {
        let msg = ArcMessage::Chunk {
            transfer_id: [1u8; 16],
            index: 42,
            hash: [0x55; 32],
            data: vec![1, 2, 3, 4, 5],
            is_last: false,
        };
        let back = roundtrip(msg);
        match back {
            ArcMessage::Chunk { index, is_last, .. } => {
                assert_eq!(index, 42);
                assert!(!is_last);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn test_transfer_offer_roundtrip() {
        let msg = ArcMessage::TransferOffer {
            transfer_id: [2u8; 16],
            kind: TransferKind::File,
            file_name: "photo.jpg".to_string(),
            total_size: 1024 * 1024,
            chunk_count: 1,
            chunk_size: 1024 * 1024,
            file_hash: [0x12; 32],
            partial_hash: [0x34; 32],
            compression: CompressionAlgo::None,
        };
        let back = roundtrip(msg);
        match back {
            ArcMessage::TransferOffer { file_name, total_size, .. } => {
                assert_eq!(file_name, "photo.jpg");
                assert_eq!(total_size, 1024 * 1024);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn test_ping_pong_roundtrip() {
        let ping = roundtrip(ArcMessage::Ping { timestamp_ms: 123456 });
        assert!(matches!(ping, ArcMessage::Ping { timestamp_ms: 123456 }));

        let pong = roundtrip(ArcMessage::Pong { timestamp_ms: 123456 });
        assert!(matches!(pong, ArcMessage::Pong { timestamp_ms: 123456 }));
    }

    #[test]
    fn test_type_name_no_secrets() {
        // INV-10: type_name must only return static strings, never containing secret values
        let msg = ArcMessage::AuthResponse { signature: [0xFFu8; 64] };
        assert_eq!(msg.type_name(), "AuthResponse");
        // The type name must NOT contain the signature bytes
        assert!(!msg.type_name().contains("FF"));
    }

    #[test]
    fn test_goodbye_roundtrip() {
        let msg = ArcMessage::Goodbye { reason: Some("user quit".to_string()) };
        let back = roundtrip(msg);
        match back {
            ArcMessage::Goodbye { reason: Some(r) } => assert_eq!(r, "user quit"),
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn test_room_member_count_roundtrip() {
        let msg = ArcMessage::RoomMemberCount { count: 3 };
        let back = roundtrip(msg);
        assert!(matches!(back, ArcMessage::RoomMemberCount { count: 3 }));
    }

    #[test]
    fn test_all_message_type_names() {
        // Ensure type_name() covers all variants without panic
        let messages = vec![
            ArcMessage::Hello { protocol_version: 1, device_id: [0; 32], nonce: [0; 32], capabilities: vec![] },
            ArcMessage::HelloAck { protocol_version: 1, device_id: [0; 32], nonce: [0; 32], selected_capabilities: vec![] },
            ArcMessage::AuthChallenge { challenge: [0; 32] },
            ArcMessage::AuthResponse { signature: [0; 64] },
            ArcMessage::AuthOk,
            ArcMessage::AuthFail { reason: AuthFailReason::BadSignature },
            ArcMessage::Ping { timestamp_ms: 0 },
            ArcMessage::Pong { timestamp_ms: 0 },
            ArcMessage::Goodbye { reason: None },
            ArcMessage::RoomMemberCount { count: 2 },
        ];
        for msg in messages {
            assert!(!msg.type_name().is_empty());
        }
    }

    #[test]
    fn test_control_padding() {
        let original_msg = b"hello control msg";
        let padded = pad_control_message(original_msg).unwrap();
        assert_eq!(padded.len(), CONTROL_PADDED_SIZE);
        
        let stripped = strip_control_padding(&padded).unwrap();
        assert_eq!(stripped, original_msg);

        // Test with a message that is exactly maximum size (510 bytes)
        let max_msg = vec![0x42u8; CONTROL_PADDED_SIZE - 2];
        let padded_max = pad_control_message(&max_msg).unwrap();
        assert_eq!(padded_max.len(), CONTROL_PADDED_SIZE);
        let stripped_max = strip_control_padding(&padded_max).unwrap();
        assert_eq!(stripped_max, max_msg.as_slice());

        // Test with a message that is too large
        let too_large_msg = vec![0x42u8; CONTROL_PADDED_SIZE - 1];
        assert!(pad_control_message(&too_large_msg).is_err());
    }

    #[test]
    fn test_control_padding_empty() {
        let empty_msg = b"";
        let padded = pad_control_message(empty_msg).unwrap();
        assert_eq!(padded.len(), CONTROL_PADDED_SIZE);
        let stripped = strip_control_padding(&padded).unwrap();
        assert_eq!(stripped, empty_msg);
    }

    #[test]
    fn test_control_padding_invalid_length() {
        let mut padded = vec![0u8; CONTROL_PADDED_SIZE];
        // Set invalid padding length indicator: 0 bytes
        padded[CONTROL_PADDED_SIZE - 2..].copy_from_slice(&0u16.to_le_bytes());
        assert!(strip_control_padding(&padded).is_err());

        // Set invalid padding length indicator: 1 byte (minimum padding length must be 2)
        padded[CONTROL_PADDED_SIZE - 2..].copy_from_slice(&1u16.to_le_bytes());
        assert!(strip_control_padding(&padded).is_err());

        // Set invalid padding length indicator: 513 bytes (greater than CONTROL_PADDED_SIZE)
        padded[CONTROL_PADDED_SIZE - 2..].copy_from_slice(&513u16.to_le_bytes());
        assert!(strip_control_padding(&padded).is_err());
    }

    #[test]
    fn test_control_padding_invalid_total_size() {
        let invalid_size = vec![0u8; 100];
        assert!(strip_control_padding(&invalid_size).is_err());
    }
}
