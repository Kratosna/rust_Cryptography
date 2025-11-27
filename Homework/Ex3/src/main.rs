use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{One, Zero};
use sha2::{Sha256, Digest};

/// Simple elliptic curve point structure
#[derive(Debug, Clone, PartialEq)]
struct Point {
    x: BigInt,
    y: BigInt,
}

/// Elliptic curve parameters (using secp256k1 parameters)
struct EllipticCurve {
    p: BigInt,  // Field prime
    n: BigInt,  // Order of the curve
    g: Point,   // Generator point
    a: BigInt,  // Curve parameter a
}

impl EllipticCurve {
    /// secp256k1 curve parameters
    fn secp256k1() -> Self {
        let p = BigInt::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
            16,
        ).unwrap();
        
        let n = BigInt::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16,
        ).unwrap();
        
        let gx = BigInt::parse_bytes(
            b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            16,
        ).unwrap();
        
        let gy = BigInt::parse_bytes(
            b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
            16,
        ).unwrap();
        
        EllipticCurve {
            p,
            n,
            g: Point { x: gx, y: gy },
            a: BigInt::zero(),
        }
    }
    
    /// Modular inverse using extended Euclidean algorithm
    fn mod_inverse(&self, a: &BigInt, m: &BigInt) -> Option<BigInt> {
        let mut t = BigInt::zero();
        let mut newt = BigInt::one();
        let mut r = m.clone();
        let mut newr = a.clone();
        
        while !newr.is_zero() {
            let quotient = &r / &newr;
            let tmp = t.clone();
            t = newt.clone();
            newt = tmp - &quotient * &newt;
            
            let tmp = r.clone();
            r = newr.clone();
            newr = tmp - quotient * newr;
        }
        
        if r > BigInt::one() {
            return None;
        }
        
        if t < BigInt::zero() {
            t = t + m;
        }
        
        Some(t)
    }
    
    /// Point addition on elliptic curve
    fn point_add(&self, p1: &Point, p2: &Point) -> Point {
        if p1.x == p2.x && p1.y == p2.y {
            // Point doubling
            let s_num = (BigInt::from(3) * &p1.x * &p1.x + &self.a) % &self.p;
            let s_denom = (BigInt::from(2) * &p1.y) % &self.p;
            let s_denom_inv = self.mod_inverse(&s_denom, &self.p).unwrap();
            let s = (s_num * s_denom_inv) % &self.p;
            
            let x3 = (&s * &s - BigInt::from(2) * &p1.x) % &self.p;
            let x3 = if x3 < BigInt::zero() { x3 + &self.p } else { x3 };
            
            let y3 = (&s * (&p1.x - &x3) - &p1.y) % &self.p;
            let y3 = if y3 < BigInt::zero() { y3 + &self.p } else { y3 };
            
            Point { x: x3, y: y3 }
        } else {
            // Regular addition
            let s_num = (&p2.y - &p1.y) % &self.p;
            let s_num = if s_num < BigInt::zero() { s_num + &self.p } else { s_num };
            
            let s_denom = (&p2.x - &p1.x) % &self.p;
            let s_denom = if s_denom < BigInt::zero() { s_denom + &self.p } else { s_denom };
            
            let s_denom_inv = self.mod_inverse(&s_denom, &self.p).unwrap();
            let s = (s_num * s_denom_inv) % &self.p;
            
            let x3 = (&s * &s - &p1.x - &p2.x) % &self.p;
            let x3 = if x3 < BigInt::zero() { x3 + &self.p } else { x3 };
            
            let y3 = (&s * (&p1.x - &x3) - &p1.y) % &self.p;
            let y3 = if y3 < BigInt::zero() { y3 + &self.p } else { y3 };
            
            Point { x: x3, y: y3 }
        }
    }
    
    /// Scalar multiplication using double-and-add
    fn scalar_mult(&self, k: &BigInt, point: &Point) -> Point {
        let mut result = None;
        let mut addend = point.clone();
        let mut scalar = k.clone();
        
        while scalar > BigInt::zero() {
            if &scalar % 2 == BigInt::one() {
                result = Some(match result {
                    None => addend.clone(),
                    Some(r) => self.point_add(&r, &addend),
                });
            }
            addend = self.point_add(&addend, &addend);
            scalar = scalar / 2;
        }
        
        result.unwrap()
    }
}

/// ECDSA signature
#[derive(Debug, Clone)]
struct Signature {
    r: BigInt,
    s: BigInt,
}

/// Hash a message to BigInt
fn hash_message(message: &[u8]) -> BigInt {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let result = hasher.finalize();
    BigInt::from_bytes_be(num_bigint::Sign::Plus, &result)
}

/// Sign a message using ECDSA (with a specific nonce for demonstration)
fn sign_with_nonce(curve: &EllipticCurve, private_key: &BigInt, message: &[u8], k: &BigInt) -> Signature {
    let z = hash_message(message);
    
    // Calculate R = k*G
    let r_point = curve.scalar_mult(k, &curve.g);
    let r = &r_point.x % &curve.n;
    
    // Calculate s = k^(-1) * (z + r*private_key) mod n
    let k_inv = curve.mod_inverse(k, &curve.n).unwrap();
    let s = (&k_inv * (&z + &r * private_key)) % &curve.n;
    
    Signature { r, s }
}

/// Recover private key from two signatures with the same nonce
fn recover_private_key(
    curve: &EllipticCurve,
    msg1: &[u8],
    sig1: &Signature,
    msg2: &[u8],
    sig2: &Signature,
) -> Option<BigInt> {
    // Verify that r values are the same (same nonce was used)
    if sig1.r != sig2.r {
        println!("Error: Signatures don't use the same nonce (r values differ)");
        return None;
    }
    
    let z1 = hash_message(msg1);
    let z2 = hash_message(msg2);
    
    println!("\nAttack Details:");
    println!("Both signatures use r = {}", sig1.r);
    println!("Message 1 hash: {}", z1);
    println!("Message 2 hash: {}", z2);
    
    // From ECDSA equations:
    // s1 = k^(-1) * (z1 + r*d) mod n
    // s2 = k^(-1) * (z2 + r*d) mod n
    //
    // Therefore:
    // s1 - s2 = k^(-1) * (z1 - z2) mod n
    // k = (z1 - z2) / (s1 - s2) mod n
    
    let s_diff = (&sig1.s - &sig2.s) % &curve.n;
    let s_diff = if s_diff < BigInt::zero() { s_diff + &curve.n } else { s_diff };
    
    let z_diff = (&z1 - &z2) % &curve.n;
    let z_diff = if z_diff < BigInt::zero() { z_diff + &curve.n } else { z_diff };
    
    // Calculate k = (z1 - z2) * (s1 - s2)^(-1) mod n
    let s_diff_inv = curve.mod_inverse(&s_diff, &curve.n)?;
    let k = (&z_diff * &s_diff_inv) % &curve.n;
    
    println!("Recovered nonce k: {}", k);
    
    // Now recover private key d from: s1 = k^(-1) * (z1 + r*d) mod n
    // Therefore: d = (s1*k - z1) * r^(-1) mod n
    let r_inv = curve.mod_inverse(&sig1.r, &curve.n)?;
    let d = ((&sig1.s * &k - &z1) * &r_inv) % &curve.n;
    let d = if d < BigInt::zero() { d + &curve.n } else { d };
    
    Some(d)
}

fn main() {
    
    let curve = EllipticCurve::secp256k1();
    
    // Generate a private key (in practice, this should be random)
    let private_key = BigInt::parse_bytes(b"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", 16).unwrap();
    
    // Calculate public key
    let public_key = curve.scalar_mult(&private_key, &curve.g);
    
    println!("Private key: {}", private_key);
    println!("Public key: ({}, {})\n", public_key.x, public_key.y);
    
    // VULNERABLE: Using the same nonce k for two different messages
    let k = BigInt::parse_bytes(b"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16).unwrap();
    
    let message1 = b"This is the first message";
    let message2 = b"This is a different message";
    
    println!("Signing Two Messages");
    println!("Message 1: {:?}", std::str::from_utf8(message1).unwrap());
    println!("Message 2: {:?}", std::str::from_utf8(message2).unwrap());
    println!("Using the SAME nonce k for both signatures (VULNERABLE!)\n");
    
    let sig1 = sign_with_nonce(&curve, &private_key, message1, &k);
    let sig2 = sign_with_nonce(&curve, &private_key, message2, &k);
    
    println!("Signature 1: r={}, s={}", sig1.r, sig1.s);
    println!("Signature 2: r={}, s={}", sig2.r, sig2.s);
    
    // Perform the attack
    println!("\nPerforming Nonce Reuse Attack:");
    
    match recover_private_key(&curve, message1, &sig1, message2, &sig2) {
        Some(recovered_key) => {
            println!("\nAttack Success!");
            println!("Recovered private key: {}", recovered_key);
            println!("Original private key:  {}", private_key);
            println!("Keys match: {}", recovered_key == private_key);
            
            if recovered_key == private_key {
                println!("\nPrivate key successfully recovered!");
                println!("This demonstrates why ECDSA must use a unique random nonce for each signature!");
            }
        }
        None => {
            println!("Failed to recover private key");
        }
    }
    
}