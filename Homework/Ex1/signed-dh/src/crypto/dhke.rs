use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// Ephemeral X25519 keypair for Diffie-Hellman
pub struct DHKeypair {
    pub sk: StaticSecret,
    pub pk: PublicKey,
}

impl DHKeypair {
    /// Generate a new ephemeral X25519 keypair
    pub fn keygen() -> Self {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = PublicKey::from(&sk);
        Self { sk, pk }
    }
}

/// Compute the shared secret from your secret key and their public key
pub fn shared_secret(sk: &StaticSecret, their_pk: &PublicKey) -> [u8; 32] {
    sk.diffie_hellman(their_pk).to_bytes()
}
