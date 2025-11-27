mod crypto;
mod io;
mod encode;

use anyhow::Result;
use rand::{rngs::OsRng, RngCore};

use crypto::signed_dh::Participant;
use encode::encode_b64::b64;
use io::readline::read_line_prompt;

fn print_separator() {
    println!("{}", "=".repeat(70));
}

fn main() -> Result<()> {

    println!();
    println!("Protocol:");
    println!("  1. Identity:  Ed25519 long-term signing keypairs");
    println!("  2. Ephemeral: X25519 DH keypairs (fresh per session)");
    println!("  3. Signature: Each party signs their ephemeral public key");
    println!("  4. Verify:    Signatures verified before computing shared secret");
    println!("  5. KDF:       HKDF-SHA3-256 derives AES key from shared secret");
    println!("  6. AEAD:      AES-256-GCM for authenticated encryption");
    println!();
    println!("Type 'exit' to quit at any prompt.\n");

    // Create Alice and Bob with identity keys
    print_separator();
    println!("Generate identity keypairs (long-term Ed25519)");
    print_separator();

    let alice = Participant::new();
    let bob = Participant::new();

    println!("\nAlice's Identity PK: {}", b64(&alice.identity.pk.to_bytes()));
    println!("Bob's Identity PK:   {}", b64(&bob.identity.pk.to_bytes()));

    // Show ephemeral keys and signatures
    println!();
    print_separator();
    println!("Generate ephemeral DH keypairs (X25519) and sign them");
    print_separator();

    let alice_msg = alice.key_exchange_message();
    let bob_msg = bob.key_exchange_message();

    println!("\nAlice's Ephemeral PK: {}", b64(alice_msg.ephemeral_pk.as_bytes()));
    println!("Alice's Signature:    {}", b64(&alice_msg.signature.to_bytes()));

    println!("\nBob's Ephemeral PK:   {}", b64(bob_msg.ephemeral_pk.as_bytes()));
    println!("Bob's Signature:      {}", b64(&bob_msg.signature.to_bytes()));

    // Verify signatures and establish session
    println!();
    print_separator();
    println!("Verify signatures and compute shared secret");
    print_separator();

    let info = b"SignedDH-Demo-v1";  // HKDF info/context string

    let alice_session = match alice.establish_session(&bob_msg, info) {
        Ok(s) => {
            println!("\n+ Alice verified Bob's signature");
            s
        }
        Err(e) => {
            println!("\n- Alice REJECTED Bob's signature: {e}");
            return Ok(());
        }
    };

    let bob_session = match bob.establish_session(&alice_msg, info) {
        Ok(s) => {
            println!("+ Bob verified Alice's signature");
            s
        }
        Err(e) => {
            println!("- Bob REJECTED Alice's signature: {e}");
            return Ok(());
        }
    };

    println!("\nShared Secret:    {}", b64(&alice_session.shared_secret));
    println!("Derived AES Key:  {}", b64(&alice_session.key));

    // Verify both derived the same key
    if alice_session.key == bob_session.key {
        println!("\n+ Both parties derived the SAME encryption key!");
    } else {
        println!("\n- ERROR: Keys don't match (this should never happen)");
        return Ok(());
    }

    // emonstrate tampering detection
    println!();
    print_separator();
    println!("Demonstrate signature verification (tampering detection)");
    print_separator();

    // Create a tampered message
    let mut tampered_msg = bob.key_exchange_message();
    let fake_ephemeral = crypto::dhke::DHKeypair::keygen();
    tampered_msg.ephemeral_pk = fake_ephemeral.pk;  // Replace with different key

    match alice.establish_session(&tampered_msg, info) {
        Ok(_) => println!("\n ERROR: Tampered message was accepted!"),
        Err(e) => println!("\n Tampered message correctly REJECTED: {e}"),
    }

    // Interactive encrypted messaging
    println!();
    print_separator();
    println!("Encrypted messaging demo (AES-256-GCM)");
    print_separator();
    println!("\nNow you can send encrypted messages between Alice and Bob.");
    println!("Alice encrypts -> Bob decrypts, then vice versa.\n");

    loop {
        // Alice sends to Bob
        let msg = read_line_prompt("Alice's message> ")?;
        if msg.eq_ignore_ascii_case("exit") {
            break;
        }

        let aad = read_line_prompt("Associated data (optional)> ")?;
        if aad.eq_ignore_ascii_case("exit") {
            break;
        }

        // Generate fresh nonce
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        // Alice encrypts
        match alice_session.encrypt(&nonce, msg.as_bytes(), aad.as_bytes()) {
            Ok(ct) => {
                println!("\n[Alice -> Bob]");
                println!("  Nonce:      {}", b64(&nonce));
                println!("  Ciphertext: {}", b64(&ct));

                // Bob decrypts
                match bob_session.decrypt(&nonce, &ct, aad.as_bytes()) {
                    Ok(pt) => {
                        println!("  Bob decrypted: '{}'\n", String::from_utf8_lossy(&pt));
                    }
                    Err(e) => {
                        println!("  Bob failed to decrypt: {e}\n");
                    }
                }
            }
            Err(e) => {
                eprintln!("  Encryption error: {e}\n");
                continue;
            }
        }

        // Bob replies to Alice
        let reply = read_line_prompt("Bob's reply> ")?;
        if reply.eq_ignore_ascii_case("exit") {
            break;
        }

        // Fresh nonce for reply
        OsRng.fill_bytes(&mut nonce);

        // Bob encrypts
        match bob_session.encrypt(&nonce, reply.as_bytes(), aad.as_bytes()) {
            Ok(ct) => {
                println!("\n[Bob -> Alice]");
                println!("  Nonce:      {}", b64(&nonce));
                println!("  Ciphertext: {}", b64(&ct));

                // Alice decrypts
                match alice_session.decrypt(&nonce, &ct, aad.as_bytes()) {
                    Ok(pt) => {
                        println!("  Alice decrypted: '{}'\n", String::from_utf8_lossy(&pt));
                    }
                    Err(e) => {
                        println!("  Alice failed to decrypt: {e}\n");
                    }
                }
            }
            Err(e) => {
                eprintln!("  Encryption error: {e}\n");
            }
        }

        println!();
    }

    println!("\nGoodbye!");
    Ok(())
}
