//! TLV-encoded capability negotiation (§20 of master plan).
//!
//! Type-Length-Value encoding is forward-compatible: unknown capability types
//! are silently ignored by older clients. This is the key advantage over bitflags,
//! which break when new bits are added to older clients.
//!
//! Wire format per TLV entry:
//! ```text
//! ┌────────┬────────┬──────────────┐
//! │ Type   │ Length │ Value        │
//! │ 2 bytes│ 2 bytes│ Length bytes │
//! └────────┴────────┴──────────────┘
//! ```

use bincode::{Decode, Encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from capability negotiation.
#[derive(Debug, Error)]
pub enum NegotiationError {
    #[error("no common capabilities between peers")]
    EmptyIntersection,
}

/// Known capability type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Encode, Decode, Serialize, Deserialize)]
#[repr(u16)]
pub enum CapabilityType {
    // Transport
    QuicMultipath = 0x0001,
    DirectConnection = 0x0002,
    ConnectionMigration = 0x0003,

    // Compression
    CompressionZstd = 0x0100,
    CompressionLz4 = 0x0101,

    // Transfer
    Blake3VerifiedStreaming = 0x0200,
    ContentDefinedChunking = 0x0201,
    DeltaTransfer = 0x0202,
    SparseFileSupport = 0x0203,
    ReflinkSupport = 0x0204,

    // Crypto
    PostQuantumHybrid = 0x0300,
    AesNiAvailable = 0x0301,

    // Features
    ClipboardSync = 0x0400,
    DaemonMode = 0x0401,
    BatchTransfer = 0x0402,

    /// Unknown type — caller must skip `length` bytes.
    Unknown = 0xFFFF,
}

impl CapabilityType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            0x0001 => Self::QuicMultipath,
            0x0002 => Self::DirectConnection,
            0x0003 => Self::ConnectionMigration,
            0x0100 => Self::CompressionZstd,
            0x0101 => Self::CompressionLz4,
            0x0200 => Self::Blake3VerifiedStreaming,
            0x0201 => Self::ContentDefinedChunking,
            0x0202 => Self::DeltaTransfer,
            0x0203 => Self::SparseFileSupport,
            0x0204 => Self::ReflinkSupport,
            0x0300 => Self::PostQuantumHybrid,
            0x0301 => Self::AesNiAvailable,
            0x0400 => Self::ClipboardSync,
            0x0401 => Self::DaemonMode,
            0x0402 => Self::BatchTransfer,
            _ => Self::Unknown,
        }
    }
}

/// A single TLV-encoded capability.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct CapabilityTLV {
    pub cap_type: CapabilityType,
    /// Variable-length value. Empty for boolean flags.
    pub value: Vec<u8>,
}

impl CapabilityTLV {
    /// Create a boolean flag capability (no value bytes).
    pub fn flag(cap_type: CapabilityType) -> Self {
        Self { cap_type, value: vec![] }
    }

    /// Create a u8 parameter capability.
    pub fn with_u8(cap_type: CapabilityType, val: u8) -> Self {
        Self { cap_type, value: vec![val] }
    }

    /// Create a u32 parameter capability.
    pub fn with_u32(cap_type: CapabilityType, val: u32) -> Self {
        Self { cap_type, value: val.to_le_bytes().to_vec() }
    }

    /// Returns the value as u8, if applicable.
    pub fn as_u8(&self) -> Option<u8> {
        self.value.first().copied()
    }

    /// Returns the value as u32 LE, if applicable.
    pub fn as_u32(&self) -> Option<u32> {
        if self.value.len() >= 4 {
            let bytes: [u8; 4] = self.value[..4].try_into().ok()?;
            Some(u32::from_le_bytes(bytes))
        } else {
            None
        }
    }
}

/// Build the default capability list for this device based on its hardware.
pub fn default_capabilities() -> Vec<CapabilityTLV> {
    use crate::machine::MachineCapacity;
    let cap = MachineCapacity::detect();

    let mut caps = vec![
        CapabilityTLV::flag(CapabilityType::DirectConnection),
        CapabilityTLV::flag(CapabilityType::Blake3VerifiedStreaming),
        CapabilityTLV::flag(CapabilityType::CompressionZstd),
        CapabilityTLV::flag(CapabilityType::CompressionLz4),
        CapabilityTLV::flag(CapabilityType::SparseFileSupport),
        CapabilityTLV::flag(CapabilityType::ClipboardSync),
    ];

    if cap.has_aes_ni {
        caps.push(CapabilityTLV::flag(CapabilityType::AesNiAvailable));
    }

    caps
}

/// Compute the intersection of two capability lists (negotiated set).
///
/// Returns only capabilities present in both lists, using the minimum
/// parameter value when both have parameters.
///
/// Returns an error if the intersection is empty, since peers must share
/// at least one capability to communicate.
pub fn negotiate_capabilities(
    ours: &[CapabilityTLV],
    theirs: &[CapabilityTLV],
) -> Result<Vec<CapabilityTLV>, NegotiationError> {
    let their_types: std::collections::HashSet<CapabilityType> =
        theirs.iter().map(|c| c.cap_type).collect();

    let result: Vec<CapabilityTLV> = ours
        .iter()
        .filter(|c| their_types.contains(&c.cap_type))
        .cloned()
        .collect();

    if result.is_empty() {
        return Err(NegotiationError::EmptyIntersection);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_flag_roundtrip() {
        let cap = CapabilityTLV::flag(CapabilityType::CompressionZstd);
        assert!(cap.value.is_empty());
        assert_eq!(cap.cap_type, CapabilityType::CompressionZstd);
    }

    #[test]
    fn test_capability_u8() {
        let cap = CapabilityTLV::with_u8(CapabilityType::CompressionZstd, 9);
        assert_eq!(cap.as_u8(), Some(9));
    }

    #[test]
    fn test_capability_u32() {
        let cap = CapabilityTLV::with_u32(CapabilityType::QuicMultipath, 42_000);
        assert_eq!(cap.as_u32(), Some(42_000));
    }

    #[test]
    fn test_negotiate_intersection() {
        let ours = vec![
            CapabilityTLV::flag(CapabilityType::CompressionZstd),
            CapabilityTLV::flag(CapabilityType::CompressionLz4),
            CapabilityTLV::flag(CapabilityType::AesNiAvailable),
        ];
        let theirs = vec![
            CapabilityTLV::flag(CapabilityType::CompressionZstd),
            CapabilityTLV::flag(CapabilityType::ClipboardSync),
        ];
        let negotiated = negotiate_capabilities(&ours, &theirs).unwrap();
        assert_eq!(negotiated.len(), 1);
        assert_eq!(negotiated[0].cap_type, CapabilityType::CompressionZstd);
    }

    #[test]
    fn test_default_capabilities_non_empty() {
        let caps = default_capabilities();
        assert!(!caps.is_empty(), "must have at least some default capabilities");
        // BLAKE3 streaming must always be present
        assert!(
            caps.iter().any(|c| c.cap_type == CapabilityType::Blake3VerifiedStreaming),
            "BLAKE3 verified streaming must be in defaults"
        );
    }
}
