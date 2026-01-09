//! # PQ-TLS: Post-Quantum TLS Implementation
//!
//! A TLS-like protocol implementation using post-quantum cryptographic primitives:
//! - **ML-KEM (Kyber)** for key encapsulation
//! - **ML-DSA (Dilithium)** for digital signatures
//! - **AES-256-GCM** for symmetric encryption
//!
//! ## Features
//!
//! - Post-quantum secure key exchange using ML-KEM-768
//! - Server authentication using ML-DSA-65 signatures
//! - Forward secrecy through ephemeral key exchange
//! - Authenticated encryption with AES-256-GCM
//!
//! ## Example
//!
//! ```rust,no_run
//! use pq_tls::{Server, Client, ServerConfig, ClientConfig};
//!
//! // Server setup
//! let server = Server::new(ServerConfig::default());
//!
//! // Client setup
//! let client = Client::new(ClientConfig::default());
//!
//! // Client initiates handshake
//! let (client_state, client_hello) = client.start_handshake().unwrap();
//!
//! // Server processes ClientHello and creates session
//! let mut server_session = server.handshake(&client_hello).unwrap();
//!
//! // Client completes handshake with server messages
//! let mut client_session = client
//!     .complete_handshake(client_state, server_session.handshake_messages())
//!     .unwrap();
//!
//! // Now both parties can exchange encrypted messages
//! let encrypted = client_session.send(b"Hello, PQ-TLS!").unwrap();
//! let decrypted = server_session.receive(&encrypted).unwrap();
//! ```

pub mod client;
pub mod config;
pub mod crypto;
pub mod protocol;
pub mod server;

pub use client::{Client, ClientConfig, ClientError, ClientSession};
pub use config::SecurityLevel;
pub use protocol::{CipherSuite, PQ_TLS_VERSION};
pub use server::{Server, ServerConfig, ServerError, ServerSession};

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_full_handshake() {
        // Create server
        let server = Server::new(ServerConfig::default());

        // Create client
        let client = Client::new(ClientConfig::default());

        // Client starts handshake
        let (client_state, client_hello) = client.start_handshake().unwrap();

        // Server processes ClientHello
        let mut server_session = server.handshake(&client_hello).unwrap();

        // Client completes handshake
        let mut client_session = client
            .complete_handshake(client_state, server_session.handshake_messages())
            .unwrap();

        // Test encrypted communication
        let message = b"Hello from client!";
        let encrypted = client_session.send(message).unwrap();
        let decrypted = server_session.receive(&encrypted).unwrap();
        assert_eq!(message.as_slice(), decrypted.as_slice());

        // Test reverse direction
        let response = b"Hello from server!";
        let encrypted_response = server_session.send(response).unwrap();
        let decrypted_response = client_session.receive(&encrypted_response).unwrap();
        assert_eq!(response.as_slice(), decrypted_response.as_slice());
    }

    #[test]
    fn test_multiple_messages() {
        let server = Server::new(ServerConfig::default());
        let client = Client::new(ClientConfig::default());

        let (client_state, client_hello) = client.start_handshake().unwrap();
        let mut server_session = server.handshake(&client_hello).unwrap();
        let mut client_session = client
            .complete_handshake(client_state, server_session.handshake_messages())
            .unwrap();

        // Send multiple messages
        for i in 0..5 {
            let msg = format!("Message {}", i);
            let encrypted = client_session.send(msg.as_bytes()).unwrap();
            let decrypted = server_session.receive(&encrypted).unwrap();
            assert_eq!(msg.as_bytes(), decrypted.as_slice());
        }
    }
}
