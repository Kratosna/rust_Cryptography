use kem_tls::{KemTlsClient, KemTlsServer};

fn main() {
    println!("KEM-TLS Protocol Implementation");
    println!("================================\n");

    // Run full handshake demo
    let mut client = KemTlsClient::new();
    let mut server = KemTlsServer::new();

    println!("1. Client generates ClientHello...");
    let client_hello = client.generate_client_hello();
    println!("   Sent {} bytes\n", client_hello.len());

    println!("2. Server processes ClientHello and generates ServerHello...");
    let server_hello = server.process_client_hello(&client_hello)
        .expect("Server handshake failed");
    println!("   Sent {} bytes\n", server_hello.len());

    println!("3. Client processes ServerHello and derives keys...");
    client.process_server_hello(&server_hello)
        .expect("Client handshake failed");
    println!("   Keys derived successfully\n");

    println!("4. Client generates Finished message...");
    let finished = client.generate_finished()
        .expect("Failed to generate Finished");
    println!("   Sent {} bytes\n", finished.len());

    println!("5. Server verifies Finished message...");
    server.verify_finished(&finished)
        .expect("Finished verification failed");
    println!("   ✓ Handshake complete!\n");

    println!("6. Exchanging encrypted application data...\n");
    
    // Client sends message
    let client_msg = b"This is a secret message from the client!";
    println!("   Client plaintext: {}", String::from_utf8_lossy(client_msg));
    let encrypted = client.encrypt_data(client_msg)
        .expect("Encryption failed");
    println!("   Encrypted: {} bytes", encrypted.len());
    
    let decrypted = server.decrypt_data(&encrypted)
        .expect("Decryption failed");
    println!("   Server decrypted: {}\n", String::from_utf8_lossy(&decrypted));

    // Server sends response
    let server_msg = b"This is a secret response from the server!";
    println!("   Server plaintext: {}", String::from_utf8_lossy(server_msg));
    let encrypted_response = server.encrypt_data(server_msg)
        .expect("Encryption failed");
    println!("   Encrypted: {} bytes", encrypted_response.len());
    
    let decrypted_response = client.decrypt_data(&encrypted_response)
        .expect("Decryption failed");
    println!("   Client decrypted: {}\n", String::from_utf8_lossy(&decrypted_response));

    println!("✓ Secure bidirectional communication established!");
}