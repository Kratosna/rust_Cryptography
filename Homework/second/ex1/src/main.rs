use pq_tls::{Client, ClientConfig, Server, ServerConfig};

fn main() {
    println!("Using: ML-KEM-768 (key exchange) + ML-DSA-65 (signatures) + AES-256-GCM\n");

    // --- Setup ---
    let server = Server::new(ServerConfig::default());
    let client = Client::new(ClientConfig::default());

    println!("[1] Client generates ephemeral ML-KEM keypair and sends ClientHello...");
    let (client_state, client_hello) = client.start_handshake().unwrap();
    println!("    ClientHello sent ({} bytes)\n", client_hello.len());

    println!("[2] Server processes ClientHello:");
    println!("- Encapsulates to client's ephemeral key → shared secret");
    println!("- Signs transcript with ML-DSA-65 key");
    println!("- Sends ServerHello + Certificate + CertificateVerify + Finished");
    let mut server_session = server.handshake(&client_hello).unwrap();
    println!("Server handshake complete\n");

    println!("[3] Client processes server messages:");
    println!("- Decapsulates ciphertext → shared secret");
    println!("- Verifies server's ML-DSA-65 signature");
    println!("- Verifies server Finished MAC");
    let mut client_session = client
        .complete_handshake(client_state, server_session.handshake_messages())
        .unwrap();
    println!("Handshake verified! \n");

    println!("[4] Sending encrypted messages with AES-256-GCM:\n");

    let msg1 = b"Hello from client!";
    let encrypted1 = client_session.send(msg1).unwrap();
    let decrypted1 = server_session.receive(&encrypted1).unwrap();
    println!("Client → Server: \"{}\"", String::from_utf8_lossy(msg1));
    println!("Ciphertext: {} bytes", encrypted1.len());
    println!("Decrypted:  \"{}\" \n", String::from_utf8_lossy(&decrypted1));

    let msg2 = b"Hello from server!";
    let encrypted2 = server_session.send(msg2).unwrap();
    let decrypted2 = client_session.receive(&encrypted2).unwrap();
    println!("Server → Client: \"{}\"", String::from_utf8_lossy(msg2));
    println!("Ciphertext: {} bytes", encrypted2.len());
    println!("Decrypted:  \"{}\" \n", String::from_utf8_lossy(&decrypted2));

    println!("PQ-TLS handshake and communication successful!");
}
