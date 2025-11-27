use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::{
    ecdh::EphemeralSecret,
    ecdsa::{SigningKey, VerifyingKey, Signature, signature::Signer, signature::Verifier},
    EncodedPoint, PublicKey, SecretKey,
    elliptic_curve::sec1::{ToEncodedPoint, FromEncodedPoint},
};
use rand::rngs::OsRng;

type HmacSha256 = Hmac<Sha256>;

// Key Schedule Functions

/// DeriveHS(g^xy): Derives the handshake secret from the shared DH secret
/// DeriveHS(g^xy): Derives the handshake secret from the shared DH secret
fn derive_hs(shared_secret: &[u8]) -> [u8; 32] {
    // 1. ES = HKDF.Extract(0, 0) - extract with zero salt and zero IKM
    let zeros = [0u8; 32];
    let (es_prk, hkdf_es) = Hkdf::<Sha256>::extract(Some(&zeros), &zeros);
    
    // 2. dES = HKDF.Expand(ES, SHA256("DerivedES"))
    let mut derived_es = [0u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(b"DerivedES");
    let des_info = hasher.finalize();
    hkdf_es.expand(&des_info, &mut derived_es).expect("Expand failed");
    
    // 3. HS = HKDF.Extract(dES, SHA256(g^xy))
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    let gxy_hash = hasher.finalize();
    
    let (hs_prk, _hkdf_hs) = Hkdf::<Sha256>::extract(Some(&derived_es), &gxy_hash);
    let mut hs = [0u8; 32];
    hs.copy_from_slice(&hs_prk);
    
    hs
}

/// KeySchedule1(g^xy): First key schedule
fn key_schedule_1(shared_secret: &[u8]) -> ([u8; 32], [u8; 32]) {
    // 1. HS = DeriveHS(g^xy)
    let hs = derive_hs(shared_secret);
    
    // Create HKDF from HS for expansion
    let hkdf = Hkdf::<Sha256>::from_prk(&hs).expect("Invalid PRK");
    
    // 2. K1C = HKDF.Expand(HS, SHA256("ClientKE"))
    let mut hasher = Sha256::new();
    hasher.update(b"ClientKE");
    let client_info = hasher.finalize();
    
    let mut k1c = [0u8; 32];
    hkdf.expand(&client_info, &mut k1c).expect("Expand failed");
    
    // 3. K1S = HKDF.Expand(HS, SHA256("ServerKE"))
    let mut hasher = Sha256::new();
    hasher.update(b"ServerKE");
    let server_info = hasher.finalize();
    
    let mut k1s = [0u8; 32];
    hkdf.expand(&server_info, &mut k1s).expect("Expand failed");
    
    (k1c, k1s)
}

/// KeySchedule2: Second key schedule with nonces and public keys
fn key_schedule_2(
    nonce_c: &[u8],
    x: &[u8],
    nonce_s: &[u8],
    y: &[u8],
    shared_secret: &[u8],
) -> ([u8; 32], [u8; 32]) {
    // 1. HS = DeriveHS(g^xy)
    let hs = derive_hs(shared_secret);
    let hkdf = Hkdf::<Sha256>::from_prk(&hs).expect("Invalid PRK");
    
    // 2. ClientKC = SHA256(nonceC || X || nonceS || Y || "ClientKC")
    let mut hasher = Sha256::new();
    hasher.update(nonce_c);
    hasher.update(x);
    hasher.update(nonce_s);
    hasher.update(y);
    hasher.update(b"ClientKC");
    let client_kc = hasher.finalize();
    
    // 3. ServerKC = SHA256(nonceC || X || nonceS || Y || "ServerKC")
    let mut hasher = Sha256::new();
    hasher.update(nonce_c);
    hasher.update(x);
    hasher.update(nonce_s);
    hasher.update(y);
    hasher.update(b"ServerKC");
    let server_kc = hasher.finalize();
    
    // 4. K2C = HKDF.Expand(HS, ClientKC)
    let mut k2c = [0u8; 32];
    hkdf.expand(&client_kc, &mut k2c).expect("Expand failed");
    
    // 5. K2S = HKDF.Expand(HS, ServerKC)
    let mut k2s = [0u8; 32];
    hkdf.expand(&server_kc, &mut k2s).expect("Expand failed");
    
    (k2c, k2s)
}

/// KeySchedule3: Third key schedule for application keys
fn key_schedule_3(
    nonce_c: &[u8],
    x: &[u8],
    nonce_s: &[u8],
    y: &[u8],
    shared_secret: &[u8],
    sigma: &[u8],
    cert_pks: &[u8],
    mac_s: &[u8],
) -> ([u8; 32], [u8; 32]) {
    // 1. HS = DeriveHS(g^xy)
    let hs = derive_hs(shared_secret);
    let hkdf_hs = Hkdf::<Sha256>::from_prk(&hs).expect("Invalid PRK");
    
    // 2. dHS = HKDF.Expand(HS, SHA256("DerivedHS"))
    let mut hasher = Sha256::new();
    hasher.update(b"DerivedHS");
    let dhs_info = hasher.finalize();
    
    let mut derived_hs = [0u8; 32];
    hkdf_hs.expand(&dhs_info, &mut derived_hs).expect("Expand failed");
    
    // 3. MS = HKDF.Extract(dHS, 0)
    let zeros = [0u8; 32];
    let (_prk, _hkdf_ms) = Hkdf::<Sha256>::extract(Some(&derived_hs), &zeros);
    let ms = _prk;
    let hkdf_ms = Hkdf::<Sha256>::from_prk(&ms).expect("Invalid PRK");
    
    // 4. ClientSKH = SHA256(nonceC || X || nonceS || Y || σ || cert_pkS || macS || "ClientEncK")
    let mut hasher = Sha256::new();
    hasher.update(nonce_c);
    hasher.update(x);
    hasher.update(nonce_s);
    hasher.update(y);
    hasher.update(sigma);
    hasher.update(cert_pks);
    hasher.update(mac_s);
    hasher.update(b"ClientEncK");
    let client_skh = hasher.finalize();
    
    // 5. ServerSKH = SHA256(nonceC || X || nonceS || Y || σ || cert_pkS || macS || "ServerEncK")
    let mut hasher = Sha256::new();
    hasher.update(nonce_c);
    hasher.update(x);
    hasher.update(nonce_s);
    hasher.update(y);
    hasher.update(sigma);
    hasher.update(cert_pks);
    hasher.update(mac_s);
    hasher.update(b"ServerEncK");
    let server_skh = hasher.finalize();
    
    // 6. K3C = HKDF.Expand(MS, ClientSKH)
    let mut k3c = [0u8; 32];
    hkdf_ms.expand(&client_skh, &mut k3c).expect("Expand failed");
    
    // 7. K3S = HKDF.Expand(MS, ServerSKH)
    let mut k3s = [0u8; 32];
    hkdf_ms.expand(&server_skh, &mut k3s).expect("Expand failed");
    
    (k3c, k3s)
}

/// Compute server signature: σ = Sign(skS, SHA256(nonceC || X || nonceS || Y || cert_pkS))
fn compute_server_signature(
    signing_key: &SigningKey,
    nonce_c: &[u8],
    x: &[u8],
    nonce_s: &[u8],
    y: &[u8],
    cert_pks: &[u8],
) -> Signature {
    let mut hasher = Sha256::new();
    hasher.update(nonce_c);
    hasher.update(x);
    hasher.update(nonce_s);
    hasher.update(y);
    hasher.update(cert_pks);
    let message_hash = hasher.finalize();
    
    signing_key.sign(&message_hash)
}

/// Verify server signature
fn verify_server_signature(
    verifying_key: &VerifyingKey,
    nonce_c: &[u8],
    x: &[u8],
    nonce_s: &[u8],
    y: &[u8],
    cert_pks: &[u8],
    signature: &Signature,
) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(nonce_c);
    hasher.update(x);
    hasher.update(nonce_s);
    hasher.update(y);
    hasher.update(cert_pks);
    let message_hash = hasher.finalize();
    
    verifying_key.verify(&message_hash, signature).is_ok()
}

/// Compute server MAC: macS = HMAC(K2S, SHA256(nonceC || X || nonceS || Y || σ || cert_pkS || "ServerMAC"))
fn compute_server_mac(
    k2s: &[u8; 32],
    nonce_c: &[u8],
    x: &[u8],
    nonce_s: &[u8],
    y: &[u8],
    sigma: &[u8],
    cert_pks: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(nonce_c);
    hasher.update(x);
    hasher.update(nonce_s);
    hasher.update(y);
    hasher.update(sigma);
    hasher.update(cert_pks);
    hasher.update(b"ServerMAC");
    let message = hasher.finalize();
    
    let mut mac = HmacSha256::new_from_slice(k2s).expect("HMAC can take key of any size");
    mac.update(&message);
    mac.finalize().into_bytes().to_vec()
}

/// Compute client MAC: macC = HMAC(K2C, SHA256(nonceC || X || nonceS || Y || σ || cert_pkS || "ClientMAC"))
fn compute_client_mac(
    k2c: &[u8; 32],
    nonce_c: &[u8],
    x: &[u8],
    nonce_s: &[u8],
    y: &[u8],
    sigma: &[u8],
    cert_pks: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(nonce_c);
    hasher.update(x);
    hasher.update(nonce_s);
    hasher.update(y);
    hasher.update(sigma);
    hasher.update(cert_pks);
    hasher.update(b"ClientMAC");
    let message = hasher.finalize();
    
    let mut mac = HmacSha256::new_from_slice(k2c).expect("HMAC can take key of any size");
    mac.update(&message);
    mac.finalize().into_bytes().to_vec()
}

/// Verify HMAC
fn verify_mac(key: &[u8; 32], message: &[u8], expected_mac: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(message);
    mac.verify_slice(expected_mac).is_ok()
}

// ============================================================================
// Handshake Protocol
// ============================================================================

struct ClientHello {
    nonce: [u8; 32],
    public_key: Vec<u8>,  // DH public key X
}

struct ServerHello {
    nonce: [u8; 32],
    public_key: Vec<u8>,  // DH public key Y
    certificate: Vec<u8>,  // Server's signing public key
    signature: Signature,
    mac: Vec<u8>,
}

struct ClientFinished {
    mac: Vec<u8>,
}

fn run_handshake() {
    
    // Server Setup: Generate long-term signing key pair
    let server_signing_key = SigningKey::random(&mut OsRng);
    let server_verifying_key = VerifyingKey::from(&server_signing_key);
    let cert_pks = server_verifying_key.to_encoded_point(false).as_bytes().to_vec();
    
    println!("Server: Generated long-term signing key pair");
    println!("Server Certificate (Public Key): {}\n", hex::encode(&cert_pks));
    
    // Step 1: Client Hello
    println!("--- Step 1: Client Hello ---");
    
    // Client generates ephemeral DH key pair
    let client_dh_secret = EphemeralSecret::random(&mut OsRng);
    let client_dh_public = PublicKey::from(&client_dh_secret);
    let x_bytes = client_dh_public.to_encoded_point(false).as_bytes().to_vec();
    
    // Client generates random nonce
    let mut nonce_c = [0u8; 32];
    rand::Rng::fill(&mut OsRng, &mut nonce_c);
    
    let client_hello = ClientHello {
        nonce: nonce_c,
        public_key: x_bytes.clone(),
    };
    
    println!("Client: Generated nonce_C: {}", hex::encode(&client_hello.nonce));
    println!("Client: Generated DH public key X: {}", hex::encode(&client_hello.public_key));
    println!("Client -> Server: ClientHello(nonce_C, X)\n");
    
    // Step 2: Server Hello + Server Finished
    println!("--- Step 2: Server Hello ---");
    
    // Server generates ephemeral DH key pair
    let server_dh_secret = EphemeralSecret::random(&mut OsRng);
    let server_dh_public = PublicKey::from(&server_dh_secret);
    let y_bytes = server_dh_public.to_encoded_point(false).as_bytes().to_vec();
    
    // Server generates random nonce
    let mut nonce_s = [0u8; 32];
    rand::Rng::fill(&mut OsRng, &mut nonce_s);
    
    println!("Server: Generated nonce_S: {}", hex::encode(&nonce_s));
    println!("Server: Generated DH public key Y: {}", hex::encode(&y_bytes));
    
    // Server computes shared secret
    let client_public_point = EncodedPoint::from_bytes(&client_hello.public_key)
        .expect("Invalid client public key");
    let client_public_key = PublicKey::from_encoded_point(&client_public_point)
        .expect("Invalid public key");
    let server_shared_secret = server_dh_secret.diffie_hellman(&client_public_key);
    let shared_secret_bytes = server_shared_secret.raw_secret_bytes();
    
    println!("Server: Computed shared secret g^xy");
    
    // Server runs KeySchedule1 and KeySchedule2
    let (k1c_server, k1s_server) = key_schedule_1(shared_secret_bytes.as_slice());
    println!("Server: Computed K1C, K1S using KeySchedule1");
    
    let (k2c_server, k2s_server) = key_schedule_2(
        &client_hello.nonce,
        &client_hello.public_key,
        &nonce_s,
        &y_bytes,
        shared_secret_bytes.as_slice(),
    );
    println!("Server: Computed K2C, K2S using KeySchedule2");
    
    // Server computes signature
    let sigma = compute_server_signature(
        &server_signing_key,
        &client_hello.nonce,
        &client_hello.public_key,
        &nonce_s,
        &y_bytes,
        &cert_pks,
    );
    println!("Server: Computed signature σ");
    
    // Server computes MAC
    let mac_s = compute_server_mac(
        &k2s_server,
        &client_hello.nonce,
        &client_hello.public_key,
        &nonce_s,
        &y_bytes,
        &sigma.to_bytes(),
        &cert_pks,
    );
    println!("Server: Computed MAC_S");
    
    let server_hello = ServerHello {
        nonce: nonce_s,
        public_key: y_bytes.clone(),
        certificate: cert_pks.clone(),
        signature: sigma,
        mac: mac_s.clone(),
    };
    
    println!("Server -> Client: ServerHello(nonce_S, Y, cert_pkS, σ, MAC_S)\n");
    
    // Step 3: Client processes Server Hello and sends Finished
    println!("--- Step 3: Client Verification & Finished ---");
    
    // Client computes shared secret
    let server_public_point = EncodedPoint::from_bytes(&server_hello.public_key)
        .expect("Invalid server public key");
    let server_public_key = PublicKey::from_encoded_point(&server_public_point)
        .expect("Invalid public key");
    let client_shared_secret = client_dh_secret.diffie_hellman(&server_public_key);
    let client_shared_secret_bytes = client_shared_secret.raw_secret_bytes();
    
    println!("Client: Computed shared secret g^xy");
    
    // Client runs KeySchedule1 and KeySchedule2
    let (k1c_client, k1s_client) = key_schedule_1(client_shared_secret_bytes.as_slice());
    println!("Client: Computed K1C, K1S using KeySchedule1");
    
    let (k2c_client, k2s_client) = key_schedule_2(
        &client_hello.nonce,
        &client_hello.public_key,
        &server_hello.nonce,
        &server_hello.public_key,
        client_shared_secret_bytes.as_slice(),
    );
    println!("Client: Computed K2C, K2S using KeySchedule2");
    
    // Client verifies server's signature
    let server_verifying_key_received = VerifyingKey::from_encoded_point(
        &EncodedPoint::from_bytes(&server_hello.certificate).expect("Invalid certificate")
    ).expect("Invalid verifying key");
    
    let signature_valid = verify_server_signature(
        &server_verifying_key_received,
        &client_hello.nonce,
        &client_hello.public_key,
        &server_hello.nonce,
        &server_hello.public_key,
        &server_hello.certificate,
        &server_hello.signature,
    );
    
    if signature_valid {
        println!("Client: Server signature verified");
    } else {
        println!("Client: Server signature verification FAILED");
        return;
    }
    
    // Client verifies server's MAC
    let mut hasher = Sha256::new();
    hasher.update(&client_hello.nonce);
    hasher.update(&client_hello.public_key);
    hasher.update(&server_hello.nonce);
    hasher.update(&server_hello.public_key);
    hasher.update(&server_hello.signature.to_bytes());
    hasher.update(&server_hello.certificate);
    hasher.update(b"ServerMAC");
    let server_mac_message = hasher.finalize();
    
    let mac_valid = verify_mac(&k2s_client, &server_mac_message, &server_hello.mac);
    
    if mac_valid {
        println!("Client: Server MAC verified");
    } else {
        println!("Client: Server MAC verification FAILED");
        return;
    }
    
    // Client computes MAC
    let mac_c = compute_client_mac(
        &k2c_client,
        &client_hello.nonce,
        &client_hello.public_key,
        &server_hello.nonce,
        &server_hello.public_key,
        &server_hello.signature.to_bytes(),
        &server_hello.certificate,
    );
    println!("Client: Computed MAC_C");
    
    let client_finished = ClientFinished {
        mac: mac_c.clone(),
    };
    
    println!("Client -> Server: ClientFinished(MAC_C)\n");
    
    // ========================================================================
    // Step 4: Server verifies Client Finished
    // ========================================================================
    println!("--- Step 4: Server Final Verification ---");
    
    // Server verifies client's MAC
    let mut hasher = Sha256::new();
    hasher.update(&client_hello.nonce);
    hasher.update(&client_hello.public_key);
    hasher.update(&server_hello.nonce);
    hasher.update(&server_hello.public_key);
    hasher.update(&server_hello.signature.to_bytes());
    hasher.update(&server_hello.certificate);
    hasher.update(b"ClientMAC");
    let client_mac_message = hasher.finalize();
    
    let client_mac_valid = verify_mac(&k2c_server, &client_mac_message, &client_finished.mac);
    
    if client_mac_valid {
        println!("Server: ✓ Client MAC verified");
    } else {
        println!("Server: ✗ Client MAC verification FAILED");
        return;
    }
    
    // ========================================================================
    // Step 5: Both parties derive application keys using KeySchedule3
    // ========================================================================
    println!("\n--- Step 5: Application Key Derivation ---");
    
    // Client derives application keys
    let (k3c_client, k3s_client) = key_schedule_3(
        &client_hello.nonce,
        &client_hello.public_key,
        &server_hello.nonce,
        &server_hello.public_key,
        client_shared_secret_bytes.as_slice(),
        &server_hello.signature.to_bytes(),
        &server_hello.certificate,
        &server_hello.mac,
    );
    println!("Client: Computed K3C, K3S using KeySchedule3");
    
    // Server derives application keys
    let (k3c_server, k3s_server) = key_schedule_3(
        &client_hello.nonce,
        &client_hello.public_key,
        &server_hello.nonce,
        &server_hello.public_key,
        shared_secret_bytes.as_slice(),
        &server_hello.signature.to_bytes(),
        &server_hello.certificate,
        &server_hello.mac,
    );
    println!("Server: Computed K3C, K3S using KeySchedule3");
    
    // Verification: Check that both parties have the same keys
    println!("\nHandshake Complete");
    println!("\nKey Agreement Verification:");
    println!("K1C match: {}", k1c_client == k1c_server);
    println!("K1S match: {}", k1s_client == k1s_server);
    println!("K2C match: {}", k2c_client == k2c_server);
    println!("K2S match: {}", k2s_client == k2s_server);
    println!("K3C match: {}", k3c_client == k3c_server);
    println!("K3S match: {}", k3s_client == k3s_server);
    
    println!("\nFinal Application Keys:");
    println!("K3C (Client Encryption Key): {}", hex::encode(k3c_client));
    println!("K3S (Server Encryption Key): {}", hex::encode(k3s_client));
    
    println!("\n Handshake successful! Secure channel established.");
}

fn main() {
    run_handshake();
}