// Stable implementation using pqcrypto-kyber
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce,
};

// Protocol version
const KEM_TLS_VERSION: u16 = 0x0304;

// Message types
const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;
const FINISHED: u8 = 20;
const APPLICATION_DATA: u8 = 23;

/// Derives keys from a shared secret using HKDF-like construction
fn derive_keys(shared_secret: &[u8], context: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut hasher = Sha256::new();
    hasher.update(b"KEM-TLS-1.3");
    hasher.update(shared_secret);
    hasher.update(context);
    let master = hasher.finalize();

    // Derive client write key
    let mut client_hasher = Sha256::new();
    client_hasher.update(&master);
    client_hasher.update(b"client write key");
    let client_key = client_hasher.finalize();

    // Derive server write key
    let mut server_hasher = Sha256::new();
    server_hasher.update(&master);
    server_hasher.update(b"server write key");
    let server_key = server_hasher.finalize();

    let mut ck = [0u8; 32];
    let mut sk = [0u8; 32];
    ck.copy_from_slice(&client_key);
    sk.copy_from_slice(&server_key);

    (ck, sk)
}

/// Represents a handshake message
#[derive(Debug, Clone)]
struct HandshakeMessage {
    msg_type: u8,
    payload: Vec<u8>,
}

impl HandshakeMessage {
    fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.msg_type);
        result.extend_from_slice(&(self.payload.len() as u32).to_be_bytes()[1..4]);
        result.extend_from_slice(&self.payload);
        result
    }

    fn deserialize(data: &[u8]) -> Result<Self, String> {
        if data.len() < 4 {
            return Err("Message too short".to_string());
        }
        let msg_type = data[0];
        let length = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + length {
            return Err("Incomplete message".to_string());
        }
        let payload = data[4..4 + length].to_vec();
        Ok(HandshakeMessage { msg_type, payload })
    }
}

/// KEM-TLS Client
pub struct KemTlsClient {
    secret_key: kyber768::SecretKey,
    public_key: kyber768::PublicKey,
    client_random: [u8; 32],
    server_random: Option<[u8; 32]>,
    shared_secret: Option<Vec<u8>>,
    client_cipher: Option<Aes256Gcm>,
    server_cipher: Option<Aes256Gcm>,
    handshake_messages: Vec<u8>,
}

impl KemTlsClient {
    pub fn new() -> Self {
        // Generate KEM keypair
        let (pk, sk) = kyber768::keypair();
        
        // Generate random nonce
        let mut client_random = [0u8; 32];
        OsRng.fill_bytes(&mut client_random);

        KemTlsClient {
            secret_key: sk,
            public_key: pk,
            client_random,
            server_random: None,
            shared_secret: None,
            client_cipher: None,
            server_cipher: None,
            handshake_messages: Vec::new(),
        }
    }

    /// Generate ClientHello message
    pub fn generate_client_hello(&mut self) -> Vec<u8> {
        let mut payload = Vec::new();
        
        // Protocol version
        payload.extend_from_slice(&KEM_TLS_VERSION.to_be_bytes());
        
        // Client random
        payload.extend_from_slice(&self.client_random);
        
        // KEM public key
        let pk_bytes = self.public_key.as_bytes();
        payload.extend_from_slice(&(pk_bytes.len() as u16).to_be_bytes());
        payload.extend_from_slice(pk_bytes);

        let msg = HandshakeMessage {
            msg_type: CLIENT_HELLO,
            payload,
        };

        let serialized = msg.serialize();
        self.handshake_messages.extend_from_slice(&serialized);
        serialized
    }

    /// Process ServerHello and derive keys
    pub fn process_server_hello(&mut self, data: &[u8]) -> Result<(), String> {
        let msg = HandshakeMessage::deserialize(data)?;
        
        if msg.msg_type != SERVER_HELLO {
            return Err("Expected ServerHello".to_string());
        }

        self.handshake_messages.extend_from_slice(data);

        let payload = &msg.payload;
        if payload.len() < 34 {
            return Err("ServerHello too short".to_string());
        }

        // Extract server random
        let mut server_random = [0u8; 32];
        server_random.copy_from_slice(&payload[2..34]);
        self.server_random = Some(server_random);

        // Extract ciphertext length and ciphertext
        let ct_len = u16::from_be_bytes([payload[34], payload[35]]) as usize;
        if payload.len() < 36 + ct_len {
            return Err("ServerHello incomplete".to_string());
        }
        let ciphertext_bytes = &payload[36..36 + ct_len];

        // Decapsulate to get shared secret
        let ct = kyber768::Ciphertext::from_bytes(ciphertext_bytes)
            .map_err(|_| "Invalid ciphertext".to_string())?;
        
        let shared_secret = kyber768::decapsulate(&ct, &self.secret_key);
        
        // Derive keys
        let mut context = Vec::new();
        context.extend_from_slice(&self.client_random);
        context.extend_from_slice(&server_random);
        
        let (client_key, server_key) = derive_keys(shared_secret.as_bytes(), &context);
        
        self.shared_secret = Some(shared_secret.as_bytes().to_vec());
        self.client_cipher = Some(Aes256Gcm::new(&client_key.into()));
        self.server_cipher = Some(Aes256Gcm::new(&server_key.into()));

        Ok(())
    }

    /// Generate Finished message
    pub fn generate_finished(&mut self) -> Result<Vec<u8>, String> {
        let mut hasher = Sha256::new();
        hasher.update(&self.handshake_messages);
        let handshake_hash = hasher.finalize();

        let mut verify_hasher = Sha256::new();
        verify_hasher.update(self.shared_secret.as_ref().unwrap());
        verify_hasher.update(b"client finished");
        verify_hasher.update(&handshake_hash);
        let verify_data = verify_hasher.finalize();

        let msg = HandshakeMessage {
            msg_type: FINISHED,
            payload: verify_data.to_vec(),
        };

        let serialized = msg.serialize();
        self.handshake_messages.extend_from_slice(&serialized);
        Ok(serialized)
    }

    /// Encrypt application data
    pub fn encrypt_data(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = self.client_cipher.as_ref()
            .ok_or("Keys not derived yet".to_string())?;

        let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        let mut result = Vec::new();
        result.push(APPLICATION_DATA);
        result.extend_from_slice(&((nonce.len() + ciphertext.len()) as u16).to_be_bytes());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    /// Decrypt application data
    pub fn decrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 3 || data[0] != APPLICATION_DATA {
            return Err("Invalid application data".to_string());
        }

        let cipher = self.server_cipher.as_ref()
            .ok_or("Keys not derived yet".to_string())?;

        let length = u16::from_be_bytes([data[1], data[2]]) as usize;
        if data.len() < 3 + length {
            return Err("Incomplete application data".to_string());
        }

        let payload = &data[3..3 + length];
        if payload.len() < 12 {
            return Err("Payload too short for nonce".to_string());
        }

        let nonce = Nonce::from_slice(&payload[..12]);
        let ciphertext = &payload[12..];

        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))
    }
}

impl Default for KemTlsClient {
    fn default() -> Self {
        Self::new()
    }
}

/// KEM-TLS Server
pub struct KemTlsServer {
    server_random: [u8; 32],
    client_random: Option<[u8; 32]>,
    shared_secret: Option<Vec<u8>>,
    client_cipher: Option<Aes256Gcm>,
    server_cipher: Option<Aes256Gcm>,
    handshake_messages: Vec<u8>,
}

impl KemTlsServer {
    pub fn new() -> Self {
        let mut server_random = [0u8; 32];
        OsRng.fill_bytes(&mut server_random);

        KemTlsServer {
            server_random,
            client_random: None,
            shared_secret: None,
            client_cipher: None,
            server_cipher: None,
            handshake_messages: Vec::new(),
        }
    }

    /// Process ClientHello and generate ServerHello
    pub fn process_client_hello(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        let msg = HandshakeMessage::deserialize(data)?;
        
        if msg.msg_type != CLIENT_HELLO {
            return Err("Expected ClientHello".to_string());
        }

        self.handshake_messages.extend_from_slice(data);

        let payload = &msg.payload;
        if payload.len() < 34 {
            return Err("ClientHello too short".to_string());
        }

        // Extract client random
        let mut client_random = [0u8; 32];
        client_random.copy_from_slice(&payload[2..34]);
        self.client_random = Some(client_random);

        // Extract client's public key
        let pk_len = u16::from_be_bytes([payload[34], payload[35]]) as usize;
        if payload.len() < 36 + pk_len {
            return Err("ClientHello incomplete".to_string());
        }
        let pk_bytes = &payload[36..36 + pk_len];

        let public_key = kyber768::PublicKey::from_bytes(pk_bytes)
            .map_err(|_| "Invalid public key".to_string())?;

        // Encapsulate to generate shared secret
        let (shared_secret, ciphertext) = kyber768::encapsulate(&public_key);

        // Derive keys
        let mut context = Vec::new();
        context.extend_from_slice(&client_random);
        context.extend_from_slice(&self.server_random);
        
        let (client_key, server_key) = derive_keys(shared_secret.as_bytes(), &context);
        
        self.shared_secret = Some(shared_secret.as_bytes().to_vec());
        self.client_cipher = Some(Aes256Gcm::new(&client_key.into()));
        self.server_cipher = Some(Aes256Gcm::new(&server_key.into()));

        // Build ServerHello
        let mut sh_payload = Vec::new();
        sh_payload.extend_from_slice(&KEM_TLS_VERSION.to_be_bytes());
        sh_payload.extend_from_slice(&self.server_random);
        
        let ct_bytes = ciphertext.as_bytes();
        sh_payload.extend_from_slice(&(ct_bytes.len() as u16).to_be_bytes());
        sh_payload.extend_from_slice(ct_bytes);

        let server_hello = HandshakeMessage {
            msg_type: SERVER_HELLO,
            payload: sh_payload,
        };

        let serialized = server_hello.serialize();
        self.handshake_messages.extend_from_slice(&serialized);
        Ok(serialized)
    }

    /// Verify client's Finished message
    pub fn verify_finished(&mut self, data: &[u8]) -> Result<(), String> {
        let msg = HandshakeMessage::deserialize(data)?;
        
        if msg.msg_type != FINISHED {
            return Err("Expected Finished".to_string());
        }

        self.handshake_messages.extend_from_slice(data);

        let hash_data = &self.handshake_messages[..self.handshake_messages.len() - data.len()];
        let mut hasher = Sha256::new();
        hasher.update(hash_data);
        let handshake_hash = hasher.finalize();

        let mut verify_hasher = Sha256::new();
        verify_hasher.update(self.shared_secret.as_ref().unwrap());
        verify_hasher.update(b"client finished");
        verify_hasher.update(&handshake_hash);
        let expected_verify = verify_hasher.finalize();

        if msg.payload.as_slice() != expected_verify.as_slice() {
            return Err("Finished verification failed".to_string());
        }

        Ok(())
    }

    /// Encrypt application data
    pub fn encrypt_data(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = self.server_cipher.as_ref()
            .ok_or("Keys not derived yet".to_string())?;

        let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        let mut result = Vec::new();
        result.push(APPLICATION_DATA);
        result.extend_from_slice(&((nonce.len() + ciphertext.len()) as u16).to_be_bytes());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    /// Decrypt application data
    pub fn decrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 3 || data[0] != APPLICATION_DATA {
            return Err("Invalid application data".to_string());
        }

        let cipher = self.client_cipher.as_ref()
            .ok_or("Keys not derived yet".to_string())?;

        let length = u16::from_be_bytes([data[1], data[2]]) as usize;
        if data.len() < 3 + length {
            return Err("Incomplete application data".to_string());
        }

        let payload = &data[3..3 + length];
        if payload.len() < 12 {
            return Err("Payload too short for nonce".to_string());
        }

        let nonce = Nonce::from_slice(&payload[..12]);
        let ciphertext = &payload[12..];

        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))
    }
}

impl Default for KemTlsServer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_handshake() {
        let mut client = KemTlsClient::new();
        let mut server = KemTlsServer::new();

        let client_hello = client.generate_client_hello();
        println!("ClientHello sent: {} bytes", client_hello.len());

        let server_hello = server.process_client_hello(&client_hello)
            .expect("Server failed to process ClientHello");
        println!("ServerHello sent: {} bytes", server_hello.len());

        client.process_server_hello(&server_hello)
            .expect("Client failed to process ServerHello");

        let finished = client.generate_finished()
            .expect("Client failed to generate Finished");
        println!("Finished sent: {} bytes", finished.len());

        server.verify_finished(&finished)
            .expect("Server failed to verify Finished");

        println!("Handshake completed successfully!");

        let plaintext = b"Hello from client!";
        let encrypted = client.encrypt_data(plaintext)
            .expect("Client encryption failed");
        println!("Encrypted message: {} bytes", encrypted.len());

        let decrypted = server.decrypt_data(&encrypted)
            .expect("Server decryption failed");
        assert_eq!(decrypted, plaintext);
        println!("Server received: {}", String::from_utf8_lossy(&decrypted));

        let response = b"Hello from server!";
        let encrypted_response = server.encrypt_data(response)
            .expect("Server encryption failed");

        let decrypted_response = client.decrypt_data(&encrypted_response)
            .expect("Client decryption failed");
        assert_eq!(decrypted_response, response);
        println!("Client received: {}", String::from_utf8_lossy(&decrypted_response));
    }

    #[test]
    fn test_key_derivation() {
        let secret = b"shared secret";
        let context = b"context data";
        
        let (client_key, server_key) = derive_keys(secret, context);
        
        assert_ne!(client_key, server_key);
        
        let (client_key2, server_key2) = derive_keys(secret, context);
        assert_eq!(client_key, client_key2);
        assert_eq!(server_key, server_key2);
    }
}