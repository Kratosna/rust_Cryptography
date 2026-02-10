use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Hash a password to a curve point (hash-to-curve for OPRF)
fn hash_to_curve(password: &[u8]) -> RistrettoPoint {
    // Use SHA-256 to hash the password, then interpret as a scalar
    // This is a simplified hash-to-curve; production should use RFC 9380
    let mut hasher = Sha256::new();
    hasher.update(b"OPAQUE-HashToCurve-");
    hasher.update(password);
    let hash = hasher.finalize();
    
    // Create a scalar from the hash and multiply by the base point
    let scalar = Scalar::from_bytes_mod_order(hash.into());
    &scalar * RISTRETTO_BASEPOINT_TABLE
}

/// Server's long-term key pair
#[derive(Debug, Clone)]
pub struct ServerLongTermKeys {
    pub secret: Scalar,
    pub public: RistrettoPoint,
}

impl ServerLongTermKeys {
    pub fn generate() -> Self {
        let secret = Scalar::random(&mut OsRng);
        let public = &secret * RISTRETTO_BASEPOINT_TABLE;
        Self { secret, public }
    }
}

/// Client's long-term key pair
#[derive(Debug, Clone)]
pub struct ClientLongTermKeys {
    pub secret: Scalar,
    pub public: RistrettoPoint,
}

impl ClientLongTermKeys {
    pub fn generate() -> Self {
        let secret = Scalar::random(&mut OsRng);
        let public = &secret * RISTRETTO_BASEPOINT_TABLE;
        Self { secret, public }
    }
}

/// Registration data stored on the server
#[derive(Debug, Clone)]
pub struct RegistrationRecord {
    pub client_public_key: RistrettoPoint,
    pub oprf_key: Scalar,
}

/// OPRF blinding factor and blinded element
#[derive(Debug)]
pub struct OprfClientState {
    pub blind: Scalar,
    pub blinded_element: RistrettoPoint,
}

/// OPRF evaluated element from server
#[derive(Debug)]
pub struct OprfServerResponse {
    pub evaluated_element: RistrettoPoint,
}

/// 3DH ephemeral keys for client
#[derive(Debug)]
pub struct ClientEphemeralKeys {
    pub secret: Scalar,
    pub public: RistrettoPoint,
}

/// 3DH ephemeral keys for server
#[derive(Debug)]
pub struct ServerEphemeralKeys {
    pub secret: Scalar,
    pub public: RistrettoPoint,
}

/// Key confirmation MACs
#[derive(Debug)]
pub struct KeyConfirmation {
    pub client_mac: Vec<u8>,
    pub server_mac: Vec<u8>,
}

/// REGISTRATION PHASE

/// Client initiates registration by generating long-term keypair
pub fn registration_start() -> ClientLongTermKeys {
    ClientLongTermKeys::generate()
}

/// Server completes registration by storing client's public key and generating OPRF key
pub fn registration_finish(client_public_key: RistrettoPoint) -> RegistrationRecord {
    let oprf_key = Scalar::random(&mut OsRng);
    RegistrationRecord {
        client_public_key,
        oprf_key,
    }
}

/// OPRF STAGE

/// Client: Blind the password for OPRF
pub fn oprf_client_blind(password: &[u8]) -> OprfClientState {
    let blind = Scalar::random(&mut OsRng);
    let pw_point = hash_to_curve(password);
    let blinded_element = pw_point * blind;
    
    OprfClientState {
        blind,
        blinded_element,
    }
}

/// Server: Evaluate the blinded element with OPRF key
pub fn oprf_server_evaluate(
    blinded_element: RistrettoPoint,
    oprf_key: &Scalar,
) -> OprfServerResponse {
    let evaluated_element = blinded_element * oprf_key;
    OprfServerResponse { evaluated_element }
}

/// Client: Unblind the evaluated element to get the OPRF output
pub fn oprf_client_finalize(
    oprf_state: &OprfClientState,
    evaluated_element: RistrettoPoint,
    password: &[u8],
) -> Vec<u8> {
    // Unblind: divide by the blind factor
    let blind_inv = oprf_state.blind.invert();
    let unblinded = evaluated_element * blind_inv;
    
    // Hash the unblinded point with the password to get the OPRF output
    let mut hasher = Sha256::new();
    hasher.update(b"OPAQUE-OPRF-");
    hasher.update(unblinded.compress().as_bytes());
    hasher.update(password);
    hasher.finalize().to_vec()
}

/// AKE STAGE: 3DH

/// Client generates ephemeral keypair for 3DH
pub fn client_generate_ephemeral() -> ClientEphemeralKeys {
    let secret = Scalar::random(&mut OsRng);
    let public = &secret * RISTRETTO_BASEPOINT_TABLE;
    ClientEphemeralKeys { secret, public }
}

/// Server generates ephemeral keypair for 3DH
pub fn server_generate_ephemeral() -> ServerEphemeralKeys {
    let secret = Scalar::random(&mut OsRng);
    let public = &secret * RISTRETTO_BASEPOINT_TABLE;
    ServerEphemeralKeys { secret, public }
}

/// 3DH-KClient: Compute shared secret on client side
/// SK = HKDF(B^x, Y^x, Y^a)
/// where:
///   a = lsk_c (client long-term secret)
///   x = ephemeral secret
///   B = lpk_s (server long-term public)
///   Y = epk_s (server ephemeral public)
pub fn three_dh_client(
    client_ltk: &ClientLongTermKeys,
    client_ephemeral: &ClientEphemeralKeys,
    server_ltk_public: &RistrettoPoint,
    server_ephemeral_public: &RistrettoPoint,
) -> [u8; 32] {
    // Compute the three DH values
    let dh1 = server_ltk_public * client_ephemeral.secret; // B^x
    let dh2 = server_ephemeral_public * client_ephemeral.secret; // Y^x
    let dh3 = server_ephemeral_public * client_ltk.secret; // Y^a
    
    // Concatenate the DH values
    let mut ikm = Vec::new();
    ikm.extend_from_slice(dh1.compress().as_bytes());
    ikm.extend_from_slice(dh2.compress().as_bytes());
    ikm.extend_from_slice(dh3.compress().as_bytes());
    
    // Derive the shared secret using HKDF
    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut sk = [0u8; 32];
    hkdf.expand(b"3DH-SharedSecret", &mut sk)
        .expect("HKDF expand failed");
    
    sk
}

/// 3DH-KServer: Compute shared secret on server side
/// SK = HKDF(X^b, X^y, A^y)
/// where:
///   b = lsk_s (server long-term secret)
///   y = ephemeral secret
///   A = lpk_c (client long-term public)
///   X = epk_c (client ephemeral public)
pub fn three_dh_server(
    server_ltk: &ServerLongTermKeys,
    server_ephemeral: &ServerEphemeralKeys,
    client_ltk_public: &RistrettoPoint,
    client_ephemeral_public: &RistrettoPoint,
) -> [u8; 32] {
    // Compute the three DH values
    let dh1 = client_ephemeral_public * server_ltk.secret; // X^b
    let dh2 = client_ephemeral_public * server_ephemeral.secret; // X^y
    let dh3 = client_ltk_public * server_ephemeral.secret; // A^y
    
    // Concatenate the DH values
    let mut ikm = Vec::new();
    ikm.extend_from_slice(dh1.compress().as_bytes());
    ikm.extend_from_slice(dh2.compress().as_bytes());
    ikm.extend_from_slice(dh3.compress().as_bytes());
    
    // Derive the shared secret using HKDF
    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut sk = [0u8; 32];
    hkdf.expand(b"3DH-SharedSecret", &mut sk)
        .expect("HKDF expand failed");
    
    sk
}

/// KEY CONFIRMATION

/// Derive key confirmation keys from the shared secret
fn derive_confirmation_keys(sk: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let hkdf = Hkdf::<Sha256>::new(None, sk);
    
    let mut k_c = vec![0u8; 32];
    let mut k_s = vec![0u8; 32];
    
    hkdf.expand(b"Key Confirmation-Kc", &mut k_c)
        .expect("HKDF expand failed");
    hkdf.expand(b"Key Confirmation-Ks", &mut k_s)
        .expect("HKDF expand failed");
    
    (k_c, k_s)
}

/// Client generates key confirmation MAC
pub fn client_key_confirmation(sk: &[u8; 32]) -> Vec<u8> {
    let (k_c, _) = derive_confirmation_keys(sk);
    
    let mut mac = HmacSha256::new_from_slice(&k_c).expect("HMAC key error");
    mac.update(b"Client KC");
    mac.finalize().into_bytes().to_vec()
}

/// Server generates key confirmation MAC
pub fn server_key_confirmation(sk: &[u8; 32]) -> Vec<u8> {
    let (_, k_s) = derive_confirmation_keys(sk);
    
    let mut mac = HmacSha256::new_from_slice(&k_s).expect("HMAC key error");
    mac.update(b"Server KC");
    mac.finalize().into_bytes().to_vec()
}

/// Verify client's key confirmation MAC
pub fn verify_client_mac(sk: &[u8; 32], received_mac: &[u8]) -> bool {
    let expected_mac = client_key_confirmation(sk);
    expected_mac == received_mac
}

/// Verify server's key confirmation MAC
pub fn verify_server_mac(sk: &[u8; 32], received_mac: &[u8]) -> bool {
    let expected_mac = server_key_confirmation(sk);
    expected_mac == received_mac
}

/// OPAQUE PROTOCOL

fn main() {
    
    println!("--- Registration Phase ---");
    
    // Client generates long-term keypair
    let client_ltk = registration_start();
    println!("Client generated long-term keypair");
    
    // Server stores client's public key and generates OPRF key
    let server_ltk = ServerLongTermKeys::generate();
    let registration_record = registration_finish(client_ltk.public);
    println!("Server completed registration");
    println!("Registration complete!\n");
    
    println!("--- Login Phase ---\n");
    
    let password = b"my_secure_password";
    
    println!("1. OPRF Stage:");
    
    // Client blinds the password
    let oprf_state = oprf_client_blind(password);
    println!("   Client: Blinded password");
    
    // Server evaluates the blinded element
    let oprf_response = oprf_server_evaluate(
        oprf_state.blinded_element,
        &registration_record.oprf_key,
    );
    println!("   Server: Evaluated blinded element");
    
    // Client unblinds to get OPRF output
    let oprf_output = oprf_client_finalize(&oprf_state, oprf_response.evaluated_element, password);
    println!("   Client: Unblinded to get OPRF output");
    println!("   OPRF output: {}\n", hex::encode(&oprf_output[..16]));
    
    
    println!("2. AKE Stage (3DH):");
    
    // Client generates ephemeral keypair
    let client_ephemeral = client_generate_ephemeral();
    println!("   Client: Generated ephemeral keypair X");
    
    // Server generates ephemeral keypair
    let server_ephemeral = server_generate_ephemeral();
    println!("   Server: Generated ephemeral keypair Y");
    
    // Both sides compute the shared secret
    let client_sk = three_dh_client(
        &client_ltk,
        &client_ephemeral,
        &server_ltk.public,
        &server_ephemeral.public,
    );
    println!("   Client: Computed shared secret SK");
    
    let server_sk = three_dh_server(
        &server_ltk,
        &server_ephemeral,
        &registration_record.client_public_key,
        &client_ephemeral.public,
    );
    println!("   Server: Computed shared secret SK");
    
    // Verify both sides computed the same key
    assert_eq!(client_sk, server_sk, "Shared secrets don't match!");
    println!("   ✓ Both sides agree on SK: {}\n", hex::encode(&client_sk[..16]));
    
    
    println!("3. Key Confirmation:");
    
    // Client generates MAC
    let client_mac = client_key_confirmation(&client_sk);
    println!("   Client: Generated MAC_c");
    
    // Server generates MAC
    let server_mac = server_key_confirmation(&server_sk);
    println!("   Server: Generated MAC_s");
    
    // Client verifies server's MAC
    let server_mac_valid = verify_server_mac(&client_sk, &server_mac);
    println!("   Client: Verified server MAC: {}", server_mac_valid);
    
    // Server verifies client's MAC
    let client_mac_valid = verify_client_mac(&server_sk, &client_mac);
    println!("   Server: Verified client MAC: {}", client_mac_valid);
    
    // FINAL RESULT
    println!("\nProtocol Complete");
    if server_mac_valid && client_mac_valid {
        println!("Authentication successful!");
        println!("Shared session key established: {}", hex::encode(&client_sk));
    } else {
        println!("Authentication failed!");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_registration() {
        let client_ltk = registration_start();
        let registration_record = registration_finish(client_ltk.public);
        
        assert_eq!(registration_record.client_public_key, client_ltk.public);
    }
    
    #[test]
    fn test_oprf_flow() {
        let password = b"test_password";
        
        // OPRF key generation (during registration)
        let oprf_key = Scalar::random(&mut OsRng);
        
        // Client blinds
        let oprf_state = oprf_client_blind(password);
        
        // Server evaluates
        let oprf_response = oprf_server_evaluate(oprf_state.blinded_element, &oprf_key);
        
        // Client finalizes
        let oprf_output = oprf_client_finalize(&oprf_state, oprf_response.evaluated_element, password);
        
        assert_eq!(oprf_output.len(), 32);
    }
    
    #[test]
    fn test_3dh_agreement() {
        let client_ltk = ClientLongTermKeys::generate();
        let server_ltk = ServerLongTermKeys::generate();
        
        let client_ephemeral = client_generate_ephemeral();
        let server_ephemeral = server_generate_ephemeral();
        
        let client_sk = three_dh_client(
            &client_ltk,
            &client_ephemeral,
            &server_ltk.public,
            &server_ephemeral.public,
        );
        
        let server_sk = three_dh_server(
            &server_ltk,
            &server_ephemeral,
            &client_ltk.public,
            &client_ephemeral.public,
        );
        
        assert_eq!(client_sk, server_sk);
    }
    
    #[test]
    fn test_key_confirmation() {
        let sk = [42u8; 32];
        
        let client_mac = client_key_confirmation(&sk);
        let server_mac = server_key_confirmation(&sk);
        
        assert!(verify_client_mac(&sk, &client_mac));
        assert!(verify_server_mac(&sk, &server_mac));
        
        // Test with wrong MAC
        let wrong_mac = vec![0u8; 32];
        assert!(!verify_client_mac(&sk, &wrong_mac));
        assert!(!verify_server_mac(&sk, &wrong_mac));
    }
    
    #[test]
    fn test_complete_protocol() {
        let password = b"secure_password_123";
        
        // Registration
        let client_ltk = registration_start();
        let server_ltk = ServerLongTermKeys::generate();
        let registration_record = registration_finish(client_ltk.public);
        
        // Login - OPRF
        let oprf_state = oprf_client_blind(password);
        let oprf_response = oprf_server_evaluate(
            oprf_state.blinded_element,
            &registration_record.oprf_key,
        );
        let _oprf_output = oprf_client_finalize(&oprf_state, oprf_response.evaluated_element, password);
        
        // AKE - 3DH
        let client_ephemeral = client_generate_ephemeral();
        let server_ephemeral = server_generate_ephemeral();
        
        let client_sk = three_dh_client(
            &client_ltk,
            &client_ephemeral,
            &server_ltk.public,
            &server_ephemeral.public,
        );
        
        let server_sk = three_dh_server(
            &server_ltk,
            &server_ephemeral,
            &client_ltk.public,
            &client_ephemeral.public,
        );
        
        assert_eq!(client_sk, server_sk);
        
        // Key Confirmation
        let client_mac = client_key_confirmation(&client_sk);
        let server_mac = server_key_confirmation(&server_sk);
        
        assert!(verify_server_mac(&client_sk, &server_mac));
        assert!(verify_client_mac(&server_sk, &client_mac));
    }
}