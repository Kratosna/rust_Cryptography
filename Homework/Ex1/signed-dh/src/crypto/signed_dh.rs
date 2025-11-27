//! Signed Diffie-Hellman Protocol
//!
//! This module implements a signed DH key exchange where:
//! 1. Each party has a long-term Ed25519 identity keypair
//! 2. Each party generates an ephemeral X25519 DH keypair
//! 3. Ephemeral public keys are signed with the identity key
//! 4. After verifying signatures, parties compute a shared secret
//! 5. HKDF derives an encryption key from the shared secret
//! 6. AES-256-GCM provides authenticated encryption

use ed25519_dalek::{Signature, VerifyingKey};
use x25519_dalek::PublicKey as DHPublicKey;

use super::signdemo::{verify_with_pk, IdentityKeypair};
use super::dhke::{DHKeypair, shared_secret};
use super::hkdf::derive_aes256gcm_key;
use super::aead::{self, Key, Nonce};

/// A participant in the Signed DH protocol
pub struct Participant {
    /// Long-term Ed25519 identity keypair
    pub identity: IdentityKeypair,
    /// Ephemeral X25519 DH keypair
    pub ephemeral: DHKeypair,
    /// Signature over our ephemeral public key
    pub sig: Signature,
}

/// Message sent during the key exchange (what you'd send over the wire)
pub struct KeyExchangeMessage {
    /// The sender's identity public key (Ed25519)
    pub identity_pk: VerifyingKey,
    /// The sender's ephemeral DH public key (X25519)
    pub ephemeral_pk: DHPublicKey,
    /// Signature over the ephemeral public key
    pub signature: Signature,
}

/// An established session with derived keys
pub struct Session {
    /// Derived AES-256-GCM key
    pub key: Key,
    /// Raw shared secret (for debugging/display)
    pub shared_secret: [u8; 32],
}

impl Participant {
    /// Create a new participant with fresh identity and ephemeral keys
    pub fn new() -> Self {
        let identity = IdentityKeypair::keygen();
        let ephemeral = DHKeypair::keygen();
        
        // Sign our own ephemeral public key
        let sig = identity.sign(ephemeral.pk.as_bytes());
        
        Self { identity, ephemeral, sig }
    }

    /// Create from existing identity (generate new ephemeral)
    pub fn with_identity(identity: IdentityKeypair) -> Self {
        let ephemeral = DHKeypair::keygen();
        let sig = identity.sign(ephemeral.pk.as_bytes());
        Self { identity, ephemeral, sig }
    }

    /// Get the key exchange message to send to the peer
    pub fn key_exchange_message(&self) -> KeyExchangeMessage {
        KeyExchangeMessage {
            identity_pk: self.identity.pk,
            ephemeral_pk: self.ephemeral.pk,
            signature: self.sig,
        }
    }

    /// Verify a peer's key exchange message and establish a session
    pub fn establish_session(
        &self,
        peer_msg: &KeyExchangeMessage,
        info: &[u8],
    ) -> Result<Session, SignedDHError> {
        // 1. Verify the peer's signature over their ephemeral key
        let valid = verify_with_pk(
            &peer_msg.identity_pk,
            peer_msg.ephemeral_pk.as_bytes(),
            &peer_msg.signature,
        );

        if !valid {
            return Err(SignedDHError::InvalidSignature);
        }

        // 2. Compute shared secret via ECDH
        let ss = shared_secret(&self.ephemeral.sk, &peer_msg.ephemeral_pk);

        // 3. Derive encryption key via HKDF
        let key = derive_aes256gcm_key(&ss, None, info);

        Ok(Session {
            key,
            shared_secret: ss,
        })
    }
}

impl Default for Participant {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    /// Encrypt a message with AES-256-GCM
    pub fn encrypt(
        &self,
        nonce: &Nonce,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        aead::encrypt(&self.key, nonce, plaintext, aad)
            .map_err(|_| SessionError::EncryptionFailed)
    }

    /// Decrypt a message with AES-256-GCM
    pub fn decrypt(
        &self,
        nonce: &Nonce,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        aead::decrypt(&self.key, nonce, ciphertext, aad)
            .map_err(|_| SessionError::DecryptionFailed)
    }
}

/// Errors during signed DH key exchange
#[derive(Debug, Clone, Copy)]
pub enum SignedDHError {
    /// The peer's signature did not verify
    InvalidSignature,
}

impl std::fmt::Display for SignedDHError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignedDHError::InvalidSignature => {
                write!(f, "Invalid signature on ephemeral public key")
            }
        }
    }
}

impl std::error::Error for SignedDHError {}

/// Errors during session encryption/decryption
#[derive(Debug, Clone, Copy)]
pub enum SessionError {
    EncryptionFailed,
    DecryptionFailed,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::EncryptionFailed => write!(f, "Encryption failed"),
            SessionError::DecryptionFailed => write!(f, "Decryption failed (auth tag mismatch)"),
        }
    }
}

impl std::error::Error for SessionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn test_signed_dh_protocol() {
        // Two participants
        let alice = Participant::new();
        let bob = Participant::new();

        // Exchange messages
        let alice_msg = alice.key_exchange_message();
        let bob_msg = bob.key_exchange_message();

        // Establish sessions
        let info = b"test_signed_dh";
        let alice_session = alice.establish_session(&bob_msg, info).unwrap();
        let bob_session = bob.establish_session(&alice_msg, info).unwrap();

        // They should derive the same key
        assert_eq!(alice_session.key, bob_session.key);
        assert_eq!(alice_session.shared_secret, bob_session.shared_secret);

        // Test encryption/decryption
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let plaintext = b"Hello, signed DH!";
        let aad = b"additional data";

        let ciphertext = alice_session.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = bob_session.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let alice = Participant::new();
        let bob = Participant::new();

        // Tamper with Bob's message (use a different ephemeral key)
        let mut tampered_msg = bob.key_exchange_message();
        let fake_ephemeral = DHKeypair::keygen();
        tampered_msg.ephemeral_pk = fake_ephemeral.pk;

        // Alice should reject the tampered message
        let result = alice.establish_session(&tampered_msg, b"test");
        assert!(matches!(result, Err(SignedDHError::InvalidSignature)));
    }
}
