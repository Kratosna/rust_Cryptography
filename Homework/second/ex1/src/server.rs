use crate::crypto::{compute_verify_data, random_bytes, KeySchedule, TrafficCipher};
use crate::protocol::*;
use ml_dsa::{KeyGen, MlDsa65};
use ml_kem::{kem::{Encapsulate, EncapsulationKey}, Encoded, EncodedSizeUser};
use rand::rngs::OsRng;
use sha3::Digest;
use signature::{Signer, SignatureEncoding};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] crate::crypto::CryptoError),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::Error),
    #[error("Invalid message type")]
    InvalidMessageType,
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
}

/// PQ-TLS Server
pub struct Server {
    /// ML-DSA signing key for server authentication
    signing_key: ml_dsa::SigningKey<MlDsa65>,
    /// ML-DSA verifying key for server authentication
    verifying_key: ml_dsa::VerifyingKey<MlDsa65>,
    /// Server configuration
    config: ServerConfig,
}

pub struct ServerConfig {
    pub cipher_suites: Vec<CipherSuite>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            cipher_suites: vec![CipherSuite::MlKem768MlDsa65Aes256Gcm],
        }
    }
}

impl Server {
    /// Create a new server with generated ML-DSA keys
    pub fn new(config: ServerConfig) -> Self {
        let mut rng = OsRng;
        let keypair = MlDsa65::key_gen(&mut rng);
        
        Self {
            signing_key: keypair.signing_key().clone(),
            verifying_key: keypair.verifying_key().clone(),
            config,
        }
    }

    /// Create a server with existing keys
    pub fn with_keys(
        signing_key: ml_dsa::SigningKey<MlDsa65>,
        verifying_key: ml_dsa::VerifyingKey<MlDsa65>,
        config: ServerConfig,
    ) -> Self {
        Self {
            signing_key,
            verifying_key,
            config,
        }
    }

    /// Handle the TLS handshake and establish a secure session
    pub fn handshake(&self, client_hello_data: &[u8]) -> Result<ServerSession, ServerError> {
        let mut handshake_messages = Vec::new();
        handshake_messages.push(client_hello_data.to_vec());

        // 1. Parse ClientHello
        let client_hello_msg = HandshakeMessage::deserialize(client_hello_data)?;
        if client_hello_msg.msg_type != MessageType::ClientHello {
            return Err(ServerError::InvalidMessageType);
        }

        let client_hello: ClientHello = bincode::deserialize(&client_hello_msg.payload)?;
        let client_random = client_hello.random;

        // 2. Select cipher suite
        let cipher_suite = self
            .config
            .cipher_suites
            .iter()
            .find(|cs| client_hello.cipher_suites.contains(cs))
            .ok_or_else(|| ServerError::HandshakeFailed("No common cipher suite".to_string()))?;

        // 3. Extract client's ML-KEM encapsulation key
        let client_kem_ek = client_hello
            .extensions
            .iter()
            .find_map(|ext| match ext {
                Extension::KeyShare { encapsulation_key } => Some(encapsulation_key.clone()),
                _ => None,
            })
            .ok_or_else(|| ServerError::HandshakeFailed("No key share".to_string()))?;

        // 4. Perform ML-KEM encapsulation
        let client_ek_encoded: Encoded<EncapsulationKey<ml_kem::MlKem768Params>> = 
            client_kem_ek.as_slice().try_into()
            .map_err(|_| ServerError::HandshakeFailed("Invalid encapsulation key".to_string()))?;
        
        let client_ek = EncapsulationKey::<ml_kem::MlKem768Params>::from_bytes(&client_ek_encoded);
        
        let mut rng = OsRng;
        let (ciphertext, shared_secret) = client_ek
            .encapsulate(&mut rng)
            .map_err(|_| ServerError::HandshakeFailed("Encapsulation failed".to_string()))?;

        // 5. Create ServerHello
        let server_random = random_bytes::<32>();
        let server_hello = ServerHello {
            version: PQ_TLS_VERSION,
            random: server_random,
            cipher_suite: *cipher_suite,
            extensions: vec![Extension::KeyShareCiphertext {
                ciphertext: ciphertext.to_vec(),
            }],
        };

        let server_hello_payload = bincode::serialize(&server_hello)?;
        let server_hello_msg = HandshakeMessage::new(MessageType::ServerHello, server_hello_payload);
        let server_hello_data = server_hello_msg.serialize()?;
        handshake_messages.push(server_hello_data.clone());

        // 6. Send Certificate
        let certificate = Certificate {
            verifying_key: self.verifying_key.encode().to_vec(),
        };
        let certificate_payload = bincode::serialize(&certificate)?;
        let certificate_msg = HandshakeMessage::new(MessageType::Certificate, certificate_payload);
        let certificate_data = certificate_msg.serialize()?;
        handshake_messages.push(certificate_data.clone());

        // 7. Create and sign CertificateVerify
        // Sign the transcript hash
        let mut transcript_hasher = sha3::Sha3_256::new();
        for msg in &handshake_messages {
            sha3::Digest::update(&mut transcript_hasher, msg);
        }
        let transcript_hash = sha3::Digest::finalize(transcript_hasher);

        let signature = self.signing_key.sign(&transcript_hash);
        let cert_verify = CertificateVerify {
            signature: signature.to_bytes().to_vec(),
        };
        let cert_verify_payload = bincode::serialize(&cert_verify)?;
        let cert_verify_msg = HandshakeMessage::new(MessageType::CertificateVerify, cert_verify_payload);
        let cert_verify_data = cert_verify_msg.serialize()?;
        handshake_messages.push(cert_verify_data.clone());

        // 8. Derive keys
        let key_schedule = KeySchedule::new(shared_secret.as_ref());
        let server_finished_key = key_schedule.derive_finished_key(b"server finished");

        // 9. Send Finished
        let verify_data = compute_verify_data(&server_finished_key, &handshake_messages);
        let finished = Finished { verify_data };
        let finished_payload = bincode::serialize(&finished)?;
        let finished_msg = HandshakeMessage::new(MessageType::Finished, finished_payload);
        let finished_data = finished_msg.serialize()?;
        handshake_messages.push(finished_data.clone());

        // 10. Create session
        let server_key = key_schedule.derive_server_write_key();
        let server_iv = key_schedule.derive_server_write_iv();
        let client_key = key_schedule.derive_client_write_key();
        let client_iv = key_schedule.derive_client_write_iv();

        let session = ServerSession {
            key_schedule,
            write_cipher: TrafficCipher::new(&server_key, &server_iv)?,
            read_cipher: TrafficCipher::new(&client_key, &client_iv)?,
            handshake_messages: vec![
                server_hello_data,
                certificate_data,
                cert_verify_data,
                finished_data,
            ],
            client_random,
            server_random,
        };

        Ok(session)
    }
}

/// Active server session after handshake
pub struct ServerSession {
    pub key_schedule: KeySchedule,
    pub write_cipher: TrafficCipher,
    pub read_cipher: TrafficCipher,
    pub handshake_messages: Vec<Vec<u8>>,
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
}

impl ServerSession {
    /// Send application data
    pub fn send(&mut self, data: &[u8]) -> Result<Vec<u8>, ServerError> {
        let (ciphertext, nonce) = self.write_cipher.encrypt(data)?;
        
        let app_data = ApplicationData {
            ciphertext,
            nonce,
            tag: vec![], // Tag is included in ciphertext by AES-GCM
        };
        
        let payload = bincode::serialize(&app_data)?;
        let msg = HandshakeMessage::new(MessageType::ApplicationData, payload);
        Ok(msg.serialize()?)
    }

    /// Receive and decrypt application data
    pub fn receive(&mut self, data: &[u8]) -> Result<Vec<u8>, ServerError> {
        let msg = HandshakeMessage::deserialize(data)?;
        if msg.msg_type != MessageType::ApplicationData {
            return Err(ServerError::InvalidMessageType);
        }

        let app_data: ApplicationData = bincode::deserialize(&msg.payload)?;
        let plaintext = self.read_cipher.decrypt(&app_data.ciphertext, &app_data.nonce)?;
        
        Ok(plaintext)
    }

    /// Get handshake messages to send to client
    pub fn handshake_messages(&self) -> &[Vec<u8>] {
        &self.handshake_messages
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_creation() {
        let config = ServerConfig::default();
        let _server = Server::new(config);
    }
}
