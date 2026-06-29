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
        Self {
            cap_type,
            value: vec![],
        }
    }

    /// Create a u8 parameter capability.
    pub fn with_u8(cap_type: CapabilityType, val: u8) -> Self {
        Self {
            cap_type,
            value: vec![val],
        }
    }

    /// Create a u32 parameter capability.
    pub fn with_u32(cap_type: CapabilityType, val: u32) -> Self {
        Self {
            cap_type,
            value: val.to_le_bytes().to_vec(),
        }
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
    let mut result = Vec::new();

    for our_cap in ours {
        if let Some(their_cap) = theirs.iter().find(|c| c.cap_type == our_cap.cap_type) {
            let negotiated_value = if our_cap.value.is_empty() || their_cap.value.is_empty() {
                vec![]
            } else if our_cap.value.len() == 1 && their_cap.value.len() == 1 {
                vec![std::cmp::min(our_cap.value[0], their_cap.value[0])]
            } else if our_cap.value.len() == 4 && their_cap.value.len() == 4 {
                if let (Some(v1), Some(v2)) = (our_cap.as_u32(), their_cap.as_u32()) {
                    std::cmp::min(v1, v2).to_le_bytes().to_vec()
                } else {
                    our_cap.value.clone()
                }
            } else {
                our_cap.value.clone()
            };

            result.push(CapabilityTLV {
                cap_type: our_cap.cap_type,
                value: negotiated_value,
            });
        }
    }

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
        assert!(
            !caps.is_empty(),
            "must have at least some default capabilities"
        );
        assert!(
            caps.iter()
                .any(|c| c.cap_type == CapabilityType::Blake3VerifiedStreaming),
            "BLAKE3 verified streaming must be in defaults"
        );
    }

    #[test]
    fn test_negotiate_capabilities_parameters() {
        let ours = vec![
            CapabilityTLV::with_u8(CapabilityType::CompressionZstd, 9),
            CapabilityTLV::with_u32(CapabilityType::QuicMultipath, 42000),
        ];
        let theirs = vec![
            CapabilityTLV::with_u8(CapabilityType::CompressionZstd, 3),
            CapabilityTLV::with_u32(CapabilityType::QuicMultipath, 50000),
        ];
        let negotiated = negotiate_capabilities(&ours, &theirs).unwrap();
        assert_eq!(negotiated.len(), 2);

        let zstd_cap = negotiated
            .iter()
            .find(|c| c.cap_type == CapabilityType::CompressionZstd)
            .unwrap();
        assert_eq!(zstd_cap.as_u8(), Some(3)); // Minimum of 9 and 3

        let mp_cap = negotiated
            .iter()
            .find(|c| c.cap_type == CapabilityType::QuicMultipath)
            .unwrap();
        assert_eq!(mp_cap.as_u32(), Some(42000)); // Minimum of 42000 and 50000
    }
}
