use crate::crypto::{compute_verify_data, random_bytes, KeySchedule, TrafficCipher};
use crate::protocol::*;
use ml_dsa::MlDsa65;
use ml_kem::{kem::{Decapsulate, DecapsulationKey}, EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use sha3::Digest;
use signature::Verifier;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
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
    #[error("Finished verification failed")]
    FinishedVerificationFailed,
}

/// PQ-TLS Client
pub struct Client {
    config: ClientConfig,
}

pub struct ClientConfig {
    pub cipher_suites: Vec<CipherSuite>,
    pub server_name: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            cipher_suites: vec![CipherSuite::MlKem768MlDsa65Aes256Gcm],
            server_name: None,
        }
    }
}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    /// Initiate the handshake by creating ClientHello
    pub fn start_handshake(&self) -> Result<(ClientHandshakeState, Vec<u8>), ClientError> {
        let mut rng = OsRng;

        // 1. Generate ML-KEM key pair
        let (decapsulation_key, encapsulation_key) = MlKem768::generate(&mut rng);

        // 2. Create ClientHello
        let client_random = random_bytes::<32>();
        let mut extensions = vec![Extension::KeyShare {
            encapsulation_key: encapsulation_key.as_bytes().to_vec(),
        }];

        if let Some(server_name) = &self.config.server_name {
            extensions.push(Extension::ServerName {
                hostname: server_name.clone(),
            });
        }

        extensions.push(Extension::SupportedVersions {
            versions: vec![PQ_TLS_VERSION],
        });

        let client_hello = ClientHello {
            version: PQ_TLS_VERSION,
            random: client_random,
            cipher_suites: self.config.cipher_suites.clone(),
            extensions,
        };

        let payload = bincode::serialize(&client_hello)?;
        let msg = HandshakeMessage::new(MessageType::ClientHello, payload);
        let client_hello_data = msg.serialize()?;

        let state = ClientHandshakeState {
            decapsulation_key,
            client_random,
            handshake_messages: vec![client_hello_data.clone()],
        };

        Ok((state, client_hello_data))
    }

    /// Complete the handshake with server messages
    pub fn complete_handshake(
        &self,
        state: ClientHandshakeState,
        server_messages: &[Vec<u8>],
    ) -> Result<ClientSession, ClientError> {
        let mut handshake_messages = state.handshake_messages;

        if server_messages.len() < 4 {
            return Err(ClientError::HandshakeFailed(
                "Incomplete server response".to_string(),
            ));
        }

        // 1. Parse ServerHello
        let server_hello_msg = HandshakeMessage::deserialize(&server_messages[0])?;
        if server_hello_msg.msg_type != MessageType::ServerHello {
            return Err(ClientError::InvalidMessageType);
        }
        handshake_messages.push(server_messages[0].clone());

        let server_hello: ServerHello = bincode::deserialize(&server_hello_msg.payload)?;
        let server_random = server_hello.random;

        // 2. Extract ML-KEM ciphertext
        let ciphertext_bytes = server_hello
            .extensions
            .iter()
            .find_map(|ext| match ext {
                Extension::KeyShareCiphertext { ciphertext } => Some(ciphertext.clone()),
                _ => None,
            })
            .ok_or_else(|| ClientError::HandshakeFailed("No key share ciphertext".to_string()))?;

        // 3. Decapsulate to get shared secret
        let ciphertext: ml_kem::Ciphertext<MlKem768> = ciphertext_bytes.as_slice().try_into()
            .map_err(|_| ClientError::HandshakeFailed("Invalid ciphertext size".to_string()))?;
        
        let shared_secret = state
            .decapsulation_key
            .decapsulate(&ciphertext)
            .map_err(|_| ClientError::HandshakeFailed("Decapsulation failed".to_string()))?;

        // 4. Parse Certificate
        let certificate_msg = HandshakeMessage::deserialize(&server_messages[1])?;
        if certificate_msg.msg_type != MessageType::Certificate {
            return Err(ClientError::InvalidMessageType);
        }
        handshake_messages.push(server_messages[1].clone());

        let certificate: Certificate = bincode::deserialize(&certificate_msg.payload)?;
        let encoded_vk: ml_dsa::EncodedVerifyingKey<MlDsa65> = certificate.verifying_key.as_slice().try_into()
            .map_err(|_| ClientError::HandshakeFailed("Invalid verifying key format".to_string()))?;
        let server_verifying_key = ml_dsa::VerifyingKey::<MlDsa65>::decode(&encoded_vk);

        // 5. Parse and verify CertificateVerify
        let cert_verify_msg = HandshakeMessage::deserialize(&server_messages[2])?;
        if cert_verify_msg.msg_type != MessageType::CertificateVerify {
            return Err(ClientError::InvalidMessageType);
        }

        let cert_verify: CertificateVerify = bincode::deserialize(&cert_verify_msg.payload)?;

        // Verify signature over transcript (WITHOUT CertificateVerify message)
        let mut transcript_hasher = sha3::Sha3_256::new();
        for msg in &handshake_messages {
            sha3::Digest::update(&mut transcript_hasher, msg);
        }
        let transcript_hash = sha3::Digest::finalize(transcript_hasher);

        let encoded_sig: ml_dsa::EncodedSignature<MlDsa65> = cert_verify.signature.as_slice().try_into()
            .map_err(|_| ClientError::HandshakeFailed("Invalid signature format".to_string()))?;
        let signature = ml_dsa::Signature::<MlDsa65>::decode(&encoded_sig)
            .ok_or_else(|| ClientError::HandshakeFailed("Signature decode failed".to_string()))?;
        
        server_verifying_key
            .verify(&transcript_hash, &signature)
            .map_err(|_| ClientError::SignatureVerificationFailed)?;

        // NOW add CertificateVerify to transcript (after verification)
        handshake_messages.push(server_messages[2].clone());

        // 6. Derive keys
        let key_schedule = KeySchedule::new(shared_secret.as_ref());
        let server_finished_key = key_schedule.derive_finished_key(b"server finished");
        let client_finished_key = key_schedule.derive_finished_key(b"client finished");

        // 7. Parse and verify server Finished
        let server_finished_msg = HandshakeMessage::deserialize(&server_messages[3])?;
        if server_finished_msg.msg_type != MessageType::Finished {
            return Err(ClientError::InvalidMessageType);
        }
        handshake_messages.push(server_messages[3].clone());

        let server_finished: Finished = bincode::deserialize(&server_finished_msg.payload)?;
        let expected_verify_data = compute_verify_data(&server_finished_key, &handshake_messages);

        if server_finished.verify_data != expected_verify_data {
            return Err(ClientError::FinishedVerificationFailed);
        }

        // 8. Send client Finished
        let client_verify_data = compute_verify_data(&client_finished_key, &handshake_messages);
        let client_finished = Finished {
            verify_data: client_verify_data,
        };
        let client_finished_payload = bincode::serialize(&client_finished)?;
        let client_finished_msg = HandshakeMessage::new(MessageType::Finished, client_finished_payload);
        let client_finished_data = client_finished_msg.serialize()?;

        // 9. Create session
        let client_key = key_schedule.derive_client_write_key();
        let client_iv = key_schedule.derive_client_write_iv();
        let server_key = key_schedule.derive_server_write_key();
        let server_iv = key_schedule.derive_server_write_iv();

        let session = ClientSession {
            key_schedule,
            write_cipher: TrafficCipher::new(&client_key, &client_iv)?,
            read_cipher: TrafficCipher::new(&server_key, &server_iv)?,
            client_finished_data,
            client_random: state.client_random,
            server_random,
            server_verifying_key,
        };

        Ok(session)
    }
}

/// Client handshake state
pub struct ClientHandshakeState {
    decapsulation_key: DecapsulationKey<ml_kem::MlKem768Params>,
    client_random: [u8; 32],
    handshake_messages: Vec<Vec<u8>>,
}

/// Active client session after handshake
pub struct ClientSession {
    pub key_schedule: KeySchedule,
    pub write_cipher: TrafficCipher,
    pub read_cipher: TrafficCipher,
    pub client_finished_data: Vec<u8>,
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
    pub server_verifying_key: ml_dsa::VerifyingKey<MlDsa65>,
}

impl ClientSession {
    /// Get the client Finished message to send to server
    pub fn get_finished_message(&self) -> &[u8] {
        &self.client_finished_data
    }

    /// Send application data
    pub fn send(&mut self, data: &[u8]) -> Result<Vec<u8>, ClientError> {
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
    pub fn receive(&mut self, data: &[u8]) -> Result<Vec<u8>, ClientError> {
        let msg = HandshakeMessage::deserialize(data)?;
        if msg.msg_type != MessageType::ApplicationData {
            return Err(ClientError::InvalidMessageType);
        }

        let app_data: ApplicationData = bincode::deserialize(&msg.payload)?;
        let plaintext = self.read_cipher.decrypt(&app_data.ciphertext, &app_data.nonce)?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let config = ClientConfig::default();
        let _client = Client::new(config);
    }

    #[test]
    fn test_client_hello_generation() {
        let config = ClientConfig::default();
        let client = Client::new(config);
        let result = client.start_handshake();
        assert!(result.is_ok());
    }
}
