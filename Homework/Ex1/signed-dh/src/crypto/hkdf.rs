use hkdf::Hkdf;
use sha3::Sha3_256;

use super::aead::Key;

/// Derive an AES-256-GCM key from a shared secret using HKDF-SHA3-256
pub fn derive_aes256gcm_key(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Key {
    let hk = Hkdf::<Sha3_256>::new(salt, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32 bytes is a valid length for HKDF-SHA3-256");
    okm
}

/// Derive arbitrary-length output key material
pub fn derive_key(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha3_256>::new(salt, ikm);
    hk.expand(info, out)
        .expect("output length should be valid for HKDF");
}
