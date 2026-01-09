use serde::{Deserialize, Serialize};

/// Protocol version identifier
pub const PQ_TLS_VERSION: u16 = 0x0304; // TLS 1.3 with PQ

/// Message types in the PQ-TLS handshake
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    ClientHello = 1,
    ServerHello = 2,
    Certificate = 11,
    CertificateVerify = 15,
    Finished = 20,
    ApplicationData = 23,
}

/// Client Hello message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub version: u16,
    pub random: [u8; 32],
    pub cipher_suites: Vec<CipherSuite>,
    pub extensions: Vec<Extension>,
}

/// Server Hello message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    pub version: u16,
    pub random: [u8; 32],
    pub cipher_suite: CipherSuite,
    pub extensions: Vec<Extension>,
}

/// Certificate message containing the ML-DSA verifying key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub verifying_key: Vec<u8>,
}

/// Certificate Verify message with ML-DSA signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateVerify {
    pub signature: Vec<u8>,
}

/// Finished message with HMAC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finished {
    pub verify_data: [u8; 32],
}

/// Cipher suites supported by PQ-TLS
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    /// ML-KEM-512 for key exchange + ML-DSA-44 for signatures + AES-256-GCM for encryption (NIST Level 1)
    MlKem512MlDsa44Aes256Gcm = 0x0001,
    /// ML-KEM-768 for key exchange + ML-DSA-65 for signatures + AES-256-GCM for encryption (NIST Level 3)
    MlKem768MlDsa65Aes256Gcm = 0x0002,
    /// ML-KEM-1024 for key exchange + ML-DSA-87 for signatures + AES-256-GCM for encryption (NIST Level 5)
    MlKem1024MlDsa87Aes256Gcm = 0x0003,
}

impl CipherSuite {
    pub fn name(&self) -> &'static str {
        match self {
            CipherSuite::MlKem512MlDsa44Aes256Gcm => "ML-KEM-512_ML-DSA-44_AES-256-GCM",
            CipherSuite::MlKem768MlDsa65Aes256Gcm => "ML-KEM-768_ML-DSA-65_AES-256-GCM",
            CipherSuite::MlKem1024MlDsa87Aes256Gcm => "ML-KEM-1024_ML-DSA-87_AES-256-GCM",
        }
    }

    pub fn security_level(&self) -> u8 {
        match self {
            CipherSuite::MlKem512MlDsa44Aes256Gcm => 1,
            CipherSuite::MlKem768MlDsa65Aes256Gcm => 3,
            CipherSuite::MlKem1024MlDsa87Aes256Gcm => 5,
        }
    }
}

/// TLS extensions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Extension {
    /// Contains the ML-KEM encapsulation key
    KeyShare { encapsulation_key: Vec<u8> },
    /// Contains the ML-KEM ciphertext
    KeyShareCiphertext { ciphertext: Vec<u8> },
    /// Server name indication
    ServerName { hostname: String },
    /// Supported versions
    SupportedVersions { versions: Vec<u16> },
}

/// Handshake message wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeMessage {
    pub msg_type: MessageType,
    pub payload: Vec<u8>,
}

impl HandshakeMessage {
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Self {
        Self { msg_type, payload }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }
}

/// Application data record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationData {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub tag: Vec<u8>,
}
