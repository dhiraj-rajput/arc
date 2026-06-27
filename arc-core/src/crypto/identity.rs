//! Ed25519 device identity and X25519 session key exchange.
//!
//! # Security Model
//!
//! Each arc device has a persistent Ed25519 keypair (`DeviceIdentity`).
//! The public key IS the device ID — a stable 32-byte identifier.
//!
//! For each session, ephemeral X25519 keys are generated and combined via HKDF
//! to produce forward-secret session keys (`SessionKeys`).
//!
//! # Security Invariants
//!
//! - INV-4: Session keys MUST be derived from ephemeral material (forward secrecy)
//! - INV-10: Secrets MUST NOT appear in process argv, env vars, or log output

use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, SharedSecret};
use zeroize::Zeroize;

/// A 32-byte device identifier (the Ed25519 public key).
pub type DeviceId = [u8; 32];

/// Errors from identity and key exchange operations.
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("signature verification failed")]
    BadSignature,
    #[error("key exchange failed: {0}")]
    KeyExchange(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// The persistent device identity.
///
/// Contains the Ed25519 signing key. The public key (verifying key) is the
/// device's stable identity — safe to share publicly.
///
/// The secret key is stored only in the OS keystore (Keychain / DPAPI / libsecret)
/// and loaded into memory only during active operations. It is zeroized on drop.
pub struct DeviceIdentity {
    signing_key: SigningKey,
}

impl DeviceIdentity {
    /// Generate a new random Ed25519 device identity.
    pub fn generate() -> Self {
        let mut secret = rand::random::<[u8; 32]>();
        let signing_key = SigningKey::from_bytes(&secret);
        secret.zeroize();
        Self { signing_key }
    }

    /// Load an identity from a raw 32-byte Ed25519 secret key.
    ///
    /// # Safety
    /// The caller must ensure `secret` was stored securely (OS keystore).
    /// Never pass a secret from argv or environment variables.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        Self { signing_key }
    }

    /// Returns this device's 32-byte public identity.
    pub fn device_id(&self) -> DeviceId {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Returns the public verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign a challenge (for authentication).
    ///
    /// The signature is detached (64 bytes) and can be verified by any party
    /// holding the device's public key (device_id).
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.signing_key.sign(message).to_bytes()
    }

    /// Verify a signature made by a peer.
    pub fn verify_peer_signature(
        peer_device_id: &DeviceId,
        message: &[u8],
        signature_bytes: &[u8; 64],
    ) -> Result<(), IdentityError> {
        use ed25519_dalek::Verifier;
        let verifying_key = VerifyingKey::from_bytes(peer_device_id)
            .map_err(|_| IdentityError::BadSignature)?;
        let sig = ed25519_dalek::Signature::from_bytes(signature_bytes);
        verifying_key
            .verify(message, &sig)
            .map_err(|_| IdentityError::BadSignature)
    }

    /// Expose secret bytes for secure storage (keychain). Use once; handle carefully.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

impl Drop for DeviceIdentity {
    fn drop(&mut self) {
        // Fields are dropped and zeroized automatically by ed25519-dalek's ZeroizeOnDrop implementation.
    }
}

// ─── Session Keys ──────────────────────────────────────────────────────────

/// Symmetric session keys derived from ephemeral X25519 key exchange.
///
/// Provides forward secrecy: even if the device identity key is compromised
/// later, past sessions cannot be decrypted.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SessionKeys {
    /// 32-byte key for encrypting messages sent TO the receiver.
    pub sender_key: [u8; 32],
    /// 32-byte key for encrypting messages sent TO the sender (from receiver).
    pub receiver_key: [u8; 32],
    /// Deterministic session ID derived from the session nonces.
    pub session_id: u32,
}

/// Our ephemeral X25519 key for one session. Consumed after key exchange.
pub struct EphemeralKeyPair {
    secret: EphemeralSecret,
    pub public: X25519PublicKey,
}

impl EphemeralKeyPair {
    /// Generate a new ephemeral keypair.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(rand_core_06::OsRng);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Perform X25519 DH and derive two session keys via HKDF-SHA256.
    ///
    /// The `nonce` is the session nonce from the Hello message (prevents replay).
    /// The `we_are_sender` flag determines which key is ours for sending.
    ///
    /// # HKDF design
    ///
    /// ```text
    /// HKDF(
    ///   ikm  = x25519_shared_secret,
    ///   salt = SHA256(our_nonce || peer_nonce),
    ///   info = b"arc-v1-session"
    /// ) → 64 bytes → split into [sender_key (32), receiver_key (32)]
    /// ```
    pub fn derive_session_keys(
        self,
        peer_public: &X25519PublicKey,
        our_nonce: &[u8; 32],
        peer_nonce: &[u8; 32],
    ) -> SessionKeys {
        let shared_secret: SharedSecret = self.secret.diffie_hellman(peer_public);

        // Salt = hash of both nonces (order-independent via sort to avoid asymmetry)
        let (n1, n2) = if our_nonce <= peer_nonce {
            (our_nonce, peer_nonce)
        } else {
            (peer_nonce, our_nonce)
        };
        let mut salt_input = [0u8; 64];
        salt_input[..32].copy_from_slice(n1);
        salt_input[32..].copy_from_slice(n2);
        let salt = blake3::hash(&salt_input);

        // Bind ephemeral public keys in the KDF context info parameter (INV-4 / KDF hardening)
        let mut info = Vec::new();
        info.extend_from_slice(b"arc-v1-session");
        let (pk1, pk2) = if self.public.to_bytes() <= peer_public.to_bytes() {
            (self.public.to_bytes(), peer_public.to_bytes())
        } else {
            (peer_public.to_bytes(), self.public.to_bytes())
        };
        info.extend_from_slice(&pk1);
        info.extend_from_slice(&pk2);

        let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), shared_secret.as_bytes());
        let mut okm = [0u8; 64];
        hk.expand(&info, &mut okm)
            .expect("HKDF expand: 64 bytes is within bounds");

        let mut sender_key = [0u8; 32];
        let mut receiver_key = [0u8; 32];
        sender_key.copy_from_slice(&okm[..32]);
        receiver_key.copy_from_slice(&okm[32..]);
        okm.zeroize();

        let salt_bytes = salt.as_bytes();
        let session_id = u32::from_le_bytes([salt_bytes[0], salt_bytes[1], salt_bytes[2], salt_bytes[3]]);

        SessionKeys {
            sender_key,
            receiver_key,
            session_id,
        }
    }
}

/// Derive a 32-byte key from a human passphrase using Argon2id for strong key strengthening.
/// Uses a static salt for P2P connection coordination.
pub fn derive_key_from_phrase(phrase: &str) -> [u8; 32] {
    use argon2::Argon2;
    let mut key = [0u8; 32];
    let salt = b"arc-p2p-salt-v1";
    let argon2 = Argon2::default();
    argon2
        .hash_password_into(phrase.as_bytes(), salt, &mut key)
        .expect("Argon2id key derivation failed");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_from_phrase() {
        let key1 = derive_key_from_phrase("decoy-delta-decor-decor-decoy-delta");
        let key2 = derive_key_from_phrase("decoy-delta-decor-decor-decoy-delta");
        let key3 = derive_key_from_phrase("different-phrase-with-same-length-abc");

        assert_eq!(key1, key2, "key derivation must be deterministic");
        assert_ne!(key1, key3, "different phrases must produce different keys");
        assert_ne!(key1, [0u8; 32], "key must not be all zeros");
    }

    #[test]
    fn test_identity_generate_and_sign() {
        let identity = DeviceIdentity::generate();
        let device_id = identity.device_id();
        let message = b"arc authentication challenge";

        let signature = identity.sign(message);
        DeviceIdentity::verify_peer_signature(&device_id, message, &signature)
            .expect("own signature must verify");
    }

    #[test]
    fn test_bad_signature_rejected() {
        let identity = DeviceIdentity::generate();
        let device_id = identity.device_id();
        let mut bad_sig = [0u8; 64];
        bad_sig[0] = 0xFF;
        assert!(
            DeviceIdentity::verify_peer_signature(&device_id, b"message", &bad_sig).is_err(),
            "bad signature must be rejected"
        );
    }

    #[test]
    fn test_session_key_derivation() {
        let alice_pair = EphemeralKeyPair::generate();
        let bob_pair = EphemeralKeyPair::generate();

        let alice_pub = alice_pair.public.clone();
        let bob_pub = bob_pair.public.clone();

        let nonce_a = [1u8; 32];
        let nonce_b = [2u8; 32];

        let alice_keys = alice_pair.derive_session_keys(&bob_pub, &nonce_a, &nonce_b);
        let bob_keys = bob_pair.derive_session_keys(&alice_pub, &nonce_b, &nonce_a);

        // Both sides must derive the same keys
        assert_eq!(alice_keys.sender_key, bob_keys.sender_key);
        assert_eq!(alice_keys.receiver_key, bob_keys.receiver_key);
        assert_eq!(alice_keys.session_id, bob_keys.session_id);
    }

    #[test]
    fn test_session_keys_differ_per_session() {
        let alice1 = EphemeralKeyPair::generate();
        let bob1 = EphemeralKeyPair::generate();
        let alice2 = EphemeralKeyPair::generate();
        let bob2 = EphemeralKeyPair::generate();

        let nonces = ([0u8; 32], [1u8; 32]);

        let keys1 = alice1.derive_session_keys(&bob1.public.clone(), &nonces.0, &nonces.1);
        let keys2 = alice2.derive_session_keys(&bob2.public.clone(), &nonces.0, &nonces.1);

        // Different ephemeral keys → different session keys (forward secrecy)
        assert_ne!(keys1.sender_key, keys2.sender_key, "session keys must be unique");
    }

    #[test]
    fn test_device_id_is_public_key() {
        let identity = DeviceIdentity::generate();
        let device_id = identity.device_id();
        // Round-trip: device_id → VerifyingKey must work
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&device_id);
        assert!(vk.is_ok(), "device_id must be a valid Ed25519 public key");
    }
}



