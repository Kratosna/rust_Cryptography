use sha3::{Digest, Sha3_256};
use base64;
use std::fs::File;
use std::io::{BufRead, BufReader};

fn main() {
    // The target hashed password in Base64 (from the assignment)
    let target = "8yQ28QbbPQYfvpta2FBSgsZTGZlFdVYMhn7ePNbaKV8=";
    let target_digest = base64::decode(target).unwrap();
    
    println!("SHA3-256 Offline Dictionary Attack ===\n");
    println!("Target (Base64): {}", target);
    println!("Looking for password...\n");
    
    // Load dictionary from file
    let dictionary = load_dictionary("Dictionary.txt");
    
    if dictionary.is_empty() {
        println!("ERROR: No passwords to try!");
        println!("Please create passwords.txt with one password per line");
        return;
    }
    
    println!("Loaded {} passwords from dictionary\n", dictionary.len());
    println!("Starting attack...\n");
    
    // Try each password from dictionary
    for (i, password) in dictionary.iter().enumerate() {
        // Show progress
        if i > 0 && i % 1000 == 0 {
            println!("Tried {} passwords...", i);
        }
        
        // Hash the password using SHA3-256
        let mut hasher = Sha3_256::new();
        hasher.update(password.as_bytes());
        let digest = hasher.finalize();
        
        // Compare with target
        if digest.as_slice() == target_digest.as_slice() {
            println!("\nPASSWORD FOUND!\n");
            println!("Password: {}", password);
            println!("\nVerification:");
            println!("  Base64: {}", base64::encode(digest));
            println!("  Target: {}", target);
            println!("  Match: TRUE");
            return;
        }
    }
    
    println!("\nPassword not found in dictionary");
    println!("\nTried {} passwords total", dictionary.len());
}

// Load passwords from dictionary file
fn load_dictionary(filename: &str) -> Vec<String> {
    let mut passwords = Vec::new();
    
    // Try to open the file
    match File::open(filename) {
        Ok(file) => {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(password) = line {
                    let trimmed = password.trim();
                    if !trimmed.is_empty() {
                        passwords.push(trimmed.to_string());
                    }
                }
            }
        }
        Err(_) => {
            println!("Could not open {}", filename);
        }
    }
    passwords

}