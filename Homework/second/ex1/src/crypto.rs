use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use sha3::{Digest, Sha3_256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionError,
    #[error("Decryption failed")]
    DecryptionError,
    #[error("Invalid key length")]
    InvalidKeyLength,
}

/// Key schedule for deriving traffic keys
pub struct KeySchedule {
    master_secret: [u8; 32],
}

impl KeySchedule {
    /// Create a new key schedule from a shared secret
    pub fn new(shared_secret: &[u8]) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(shared_secret);
        let master_secret: [u8; 32] = hasher.finalize().into();
        
        Self { master_secret }
    }

    /// Derive client write key
    pub fn derive_client_write_key(&self) -> [u8; 32] {
        self.hkdf_expand(b"client write key")
    }

    /// Derive server write key
    pub fn derive_server_write_key(&self) -> [u8; 32] {
        self.hkdf_expand(b"server write key")
    }

    /// Derive client write IV
    pub fn derive_client_write_iv(&self) -> [u8; 12] {
        let key = self.hkdf_expand(b"client write iv");
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&key[..12]);
        iv
    }

    /// Derive server write IV
    pub fn derive_server_write_iv(&self) -> [u8; 12] {
        let key = self.hkdf_expand(b"server write iv");
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&key[..12]);
        iv
    }

    /// Derive finished key for handshake verification
    pub fn derive_finished_key(&self, label: &[u8]) -> [u8; 32] {
        self.hkdf_expand(label)
    }

    /// HKDF-Expand-like function using SHA3
    fn hkdf_expand(&self, info: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.master_secret);
        hasher.update(info);
        hasher.finalize().into()
    }
}

/// Compute verify data for Finished message
pub fn compute_verify_data(
    finished_key: &[u8; 32],
    handshake_messages: &[Vec<u8>],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    
    // Hash all handshake messages
    for msg in handshake_messages {
        hasher.update(msg);
    }
    let transcript_hash = hasher.finalize();
    
    // HMAC-like construction
    let mut hmac_hasher = Sha3_256::new();
    hmac_hasher.update(finished_key);
    hmac_hasher.update(&transcript_hash);
    
    hmac_hasher.finalize().into()
}

/// Traffic encryption state
pub struct TrafficCipher {
    cipher: Aes256Gcm,
    iv: [u8; 12],
    sequence_number: u64,
}

impl TrafficCipher {
    pub fn new(key: &[u8; 32], iv: &[u8; 12]) -> Result<Self, CryptoError> {
        let cipher = Aes256Gcm::new(key.into());
        Ok(Self {
            cipher,
            iv: *iv,
            sequence_number: 0,
        })
    }

    /// Encrypt application data
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let nonce = self.compute_nonce();
        let nonce_obj = Nonce::from_slice(&nonce);
        
        let ciphertext = self
            .cipher
            .encrypt(nonce_obj, plaintext)
            .map_err(|_| CryptoError::EncryptionError)?;
        
        self.sequence_number += 1;
        Ok((ciphertext, nonce.to_vec()))
    }

    /// Decrypt application data
    pub fn decrypt(&mut self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::DecryptionError);
        }
        
        let nonce_obj = Nonce::from_slice(nonce);
        let plaintext = self
            .cipher
            .decrypt(nonce_obj, ciphertext)
            .map_err(|_| CryptoError::DecryptionError)?;
        
        self.sequence_number += 1;
        Ok(plaintext)
    }

    /// Compute nonce by XORing IV with sequence number
    fn compute_nonce(&self) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq_bytes = self.sequence_number.to_be_bytes();
        
        // XOR the last 8 bytes with the sequence number
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        
        nonce
    }
}

/// Generate random bytes
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let shared_secret = b"shared_secret_for_testing";
        let schedule = KeySchedule::new(shared_secret);
        
        let client_key = schedule.derive_client_write_key();
        let server_key = schedule.derive_server_write_key();
        
        // Keys should be different
        assert_ne!(client_key, server_key);
    }

    #[test]
    fn test_encryption_decryption() {
        let key = random_bytes::<32>();
        let iv = random_bytes::<12>();
        
        let mut cipher = TrafficCipher::new(&key, &iv).unwrap();
        let plaintext = b"Hello, PQ-TLS!";
        
        let (ciphertext, nonce) = cipher.encrypt(plaintext).unwrap();
        
        // Create new cipher with same key/IV
        let mut decipher = TrafficCipher::new(&key, &iv).unwrap();
        let decrypted = decipher.decrypt(&ciphertext, &nonce).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
