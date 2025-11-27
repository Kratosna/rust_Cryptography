use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

/// Long-term identity keypair for signing
pub struct IdentityKeypair {
    pub sk: SigningKey,
    pub pk: VerifyingKey,
}

impl IdentityKeypair {
    /// Generate a new Ed25519 identity keypair
    pub fn keygen() -> Self {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        Self { sk, pk }
    }

    /// Sign arbitrary data
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.sk.sign(data)
    }

    /// Verify a signature against this keypair's public key
    pub fn verify(&self, data: &[u8], sig: &Signature) -> bool {
        self.pk.verify(data, sig).is_ok()
    }
}

/// Verify a signature using a standalone public key
pub fn verify_with_pk(pk: &VerifyingKey, data: &[u8], sig: &Signature) -> bool {
    pk.verify(data, sig).is_ok()
}
