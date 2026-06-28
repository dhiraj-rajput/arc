//! Symmetric encryption: ChaCha20-Poly1305 and AES-256-GCM.
//!
//! # Cipher Selection
//!
//! AES-256-GCM is selected when hardware AES-NI is available (x86_64).
//! ChaCha20-Poly1305 is used otherwise (ARM, RISC-V, older x86).
//! Both provide 256-bit symmetric security, which is quantum-resistant
//! at the symmetric layer (Grover's algorithm only halves key strength).
//!
//! # Nonce Construction (INV-5)
//!
//! Nonces are deterministic and never reuse within a session:
//! ```text
//! nonce[0]    = direction (0x01 = sender→receiver, 0x02 = receiver→sender)
//! nonce[1..5] = session_id (u32 LE) — identifies the arc session
//! nonce[5..9] = message_index (u32 LE) — monotonic per direction
//! nonce[9..12] = 0x00 padding
//! ```
//! This construction is from the master plan §17.3 / INV-5.

use aes_gcm::{
    Aes256Gcm,
    Nonce as AesNonce,
    aead::{Aead as AesAead, KeyInit as AesKeyInit},
};
use chacha20poly1305::{
    ChaCha20Poly1305,
    Nonce as ChaChaNonce,
    aead::{Aead as ChachaAead, KeyInit as ChachaKeyInit},
};
use thiserror::Error;

use crate::machine::MachineCapacity;

/// The symmetric cipher suite in use for this session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CipherSuite {
    /// ChaCha20-Poly1305 with BLAKE3. Default on non-x86_64.
    ChaCha20Poly1305Blake3 = 0x0001,
    /// AES-256-GCM with BLAKE3. Used when AES-NI is available.
    Aes256GcmBlake3 = 0x0002,
}

impl CipherSuite {
    /// Auto-select the best cipher suite for this machine.
    pub fn auto_detect() -> Self {
        if MachineCapacity::detect().prefer_aes_gcm() {
            Self::Aes256GcmBlake3
        } else {
            Self::ChaCha20Poly1305Blake3
        }
    }
}

/// Errors from encryption/decryption operations.
#[derive(Debug, Error)]
pub enum CipherError {
    #[error("encryption failed")]
    EncryptFailed,
    #[error("decryption failed")]
    DecryptFailed,
}

/// Message direction for nonce construction.
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Direction {
    /// Sender → Receiver
    ToReceiver = 0x01,
    /// Receiver → Sender
    ToSender = 0x02,
}

/// Build a 12-byte nonce that is unique within a session.
///
/// # INV-5 guarantee
/// For a given (session_id, direction), `message_index` must be strictly
/// monotonically increasing. The caller is responsible for maintaining the counter.
pub fn build_nonce(session_id: u32, message_index: u32, direction: Direction) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0] = direction as u8;
    nonce[1..5].copy_from_slice(&session_id.to_le_bytes());
    nonce[5..9].copy_from_slice(&message_index.to_le_bytes());
    // bytes [9..12] remain 0
    nonce
}

/// Encrypt a plaintext chunk with the given key and nonce.
///
/// Returns the ciphertext (includes 16-byte Poly1305/GCM authentication tag).
///
/// # INV-1
/// File content MUST only appear inside the returned ciphertext.
pub fn encrypt_chunk(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    plaintext: &[u8],
    suite: CipherSuite,
) -> Result<Vec<u8>, CipherError> {
    match suite {
        CipherSuite::ChaCha20Poly1305Blake3 => {
            use ChachaAead;
            use ChachaKeyInit;
            let cipher = ChaCha20Poly1305::new_from_slice(key).expect("valid 32-byte key");
            let nonce = ChaChaNonce::from_slice(nonce_bytes);
            cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| CipherError::EncryptFailed)
        }
        CipherSuite::Aes256GcmBlake3 => {
            use AesAead;
            use AesKeyInit;
            let cipher = Aes256Gcm::new_from_slice(key).expect("valid 32-byte key");
            let nonce = AesNonce::from_slice(nonce_bytes);
            cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| CipherError::EncryptFailed)
        }
    }
}

/// Decrypt and authenticate a ciphertext chunk.
///
/// Returns the plaintext on success, or `CipherError::DecryptFailed` if
/// the authentication tag does not match (data was tampered with).
pub fn decrypt_chunk(
    key: &[u8; 32],
    nonce_bytes: &[u8; 12],
    ciphertext: &[u8],
    suite: CipherSuite,
) -> Result<Vec<u8>, CipherError> {
    match suite {
        CipherSuite::ChaCha20Poly1305Blake3 => {
            use ChachaAead;
            use ChachaKeyInit;
            let cipher = ChaCha20Poly1305::new_from_slice(key).expect("valid 32-byte key");
            let nonce = ChaChaNonce::from_slice(nonce_bytes);
            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| CipherError::DecryptFailed)
        }
        CipherSuite::Aes256GcmBlake3 => {
            use AesAead;
            use AesKeyInit;
            let cipher = Aes256Gcm::new_from_slice(key).expect("valid 32-byte key");
            let nonce = AesNonce::from_slice(nonce_bytes);
            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| CipherError::DecryptFailed)
        }
    }
}

/// Generate a cryptographically random 32-byte key.
pub fn generate_key() -> [u8; 32] {
    rand::random()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(suite: CipherSuite) {
        let key = generate_key();
        let nonce = build_nonce(42, 0, Direction::ToReceiver);
        let plaintext = b"arc secure file transfer chunk data";

        let ciphertext = encrypt_chunk(&key, &nonce, plaintext, suite)
            .expect("encryption must succeed");

        assert_ne!(&ciphertext, plaintext, "ciphertext must differ from plaintext");
        assert!(
            ciphertext.len() > plaintext.len(),
            "ciphertext must include auth tag"
        );

        let recovered = decrypt_chunk(&key, &nonce, &ciphertext, suite)
            .expect("decryption must succeed");

        assert_eq!(recovered, plaintext, "roundtrip must recover original plaintext");
    }

    #[test]
    fn test_chacha20_roundtrip() {
        roundtrip(CipherSuite::ChaCha20Poly1305Blake3);
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        roundtrip(CipherSuite::Aes256GcmBlake3);
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let key = generate_key();
        let nonce = build_nonce(1, 0, Direction::ToReceiver);
        let plaintext = b"important data";

        let mut ciphertext = encrypt_chunk(&key, &nonce, plaintext, CipherSuite::ChaCha20Poly1305Blake3)
            .unwrap();

        // Flip a bit in the middle of the ciphertext
        let mid = ciphertext.len() / 2;
        ciphertext[mid] ^= 0xFF;

        assert!(
            decrypt_chunk(&key, &nonce, &ciphertext, CipherSuite::ChaCha20Poly1305Blake3).is_err(),
            "tampered ciphertext must be rejected"
        );
    }

    #[test]
    fn test_wrong_key_rejected() {
        let key1 = generate_key();
        let key2 = generate_key();
        let nonce = build_nonce(0, 0, Direction::ToReceiver);
        let ciphertext = encrypt_chunk(&key1, &nonce, b"data", CipherSuite::ChaCha20Poly1305Blake3).unwrap();

        assert!(
            decrypt_chunk(&key2, &nonce, &ciphertext, CipherSuite::ChaCha20Poly1305Blake3).is_err(),
            "wrong key must be rejected"
        );
    }

    #[test]
    fn test_nonce_uniqueness() {
        // INV-5: all nonces within a session must be unique
        use std::collections::HashSet;
        let mut nonces = HashSet::new();
        for i in 0..10_000u32 {
            let n = build_nonce(42, i, Direction::ToReceiver);
            assert!(nonces.insert(n), "nonce {i} was not unique!");
        }
        // Also check direction creates different nonces
        for i in 0..100u32 {
            let n_to_recv = build_nonce(1, i, Direction::ToReceiver);
            let n_to_send = build_nonce(1, i, Direction::ToSender);
            assert_ne!(n_to_recv, n_to_send, "direction must differentiate nonces");
        }
    }

    #[test]
    fn test_auto_detect_suite() {
        // Just verify it doesn't panic
        let suite = CipherSuite::auto_detect();
        assert!(matches!(
            suite,
            CipherSuite::ChaCha20Poly1305Blake3 | CipherSuite::Aes256GcmBlake3
        ));
    }

    proptest::proptest! {
        #[test]
        fn test_proptest_roundtrip_chacha20(ref s in "\\PC*") {
            let key = generate_key();
            let nonce = build_nonce(100, 0, Direction::ToReceiver);
            let bytes = s.as_bytes();
            let ciphertext = encrypt_chunk(&key, &nonce, bytes, CipherSuite::ChaCha20Poly1305Blake3).unwrap();
            let recovered = decrypt_chunk(&key, &nonce, &ciphertext, CipherSuite::ChaCha20Poly1305Blake3).unwrap();
            assert_eq!(recovered, bytes);
        }

        #[test]
        fn test_proptest_roundtrip_aes(ref s in "\\PC*") {
            let key = generate_key();
            let nonce = build_nonce(100, 0, Direction::ToReceiver);
            let bytes = s.as_bytes();
            let ciphertext = encrypt_chunk(&key, &nonce, bytes, CipherSuite::Aes256GcmBlake3).unwrap();
            let recovered = decrypt_chunk(&key, &nonce, &ciphertext, CipherSuite::Aes256GcmBlake3).unwrap();
            assert_eq!(recovered, bytes);
        }
    }
}



