use aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};

pub type Key = [u8; 32];
pub type Nonce = [u8; 12];

/// Encrypt plaintext with AES-256-GCM
/// Returns ciphertext || authentication tag (16 bytes)
pub fn encrypt(
    key: &Key,
    nonce: &Nonce,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let nonce = AesNonce::from_slice(nonce);
    cipher.encrypt(nonce, aead::Payload {
        msg: plaintext,
        aad: associated_data,
    })
}

/// Decrypt ciphertext with AES-256-GCM
pub fn decrypt(
    key: &Key,
    nonce: &Nonce,
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let nonce = AesNonce::from_slice(nonce);
    cipher.decrypt(nonce, aead::Payload {
        msg: ciphertext,
        aad: associated_data,
    })
}
