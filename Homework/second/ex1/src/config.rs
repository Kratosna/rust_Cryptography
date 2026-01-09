//! Parameter set configurations for different security levels
//!
//! This module provides type-safe parameter set selection for ML-KEM and ML-DSA.

use crate::protocol::CipherSuite;

/// Security level selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// NIST Level 1 - Comparable to AES-128 (quantum: 64-bit security)
    Level1,
    /// NIST Level 3 - Comparable to AES-192 (quantum: 128-bit security) - Recommended
    Level3,
    /// NIST Level 5 - Comparable to AES-256 (quantum: 256-bit security)
    Level5,
}

impl SecurityLevel {
    /// Get the cipher suite for this security level
    pub fn cipher_suite(&self) -> CipherSuite {
        match self {
            SecurityLevel::Level1 => CipherSuite::MlKem512MlDsa44Aes256Gcm,
            SecurityLevel::Level3 => CipherSuite::MlKem768MlDsa65Aes256Gcm,
            SecurityLevel::Level5 => CipherSuite::MlKem1024MlDsa87Aes256Gcm,
        }
    }

    /// Get all supported cipher suites up to and including this level
    pub fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        match self {
            SecurityLevel::Level1 => vec![CipherSuite::MlKem512MlDsa44Aes256Gcm],
            SecurityLevel::Level3 => vec![
                CipherSuite::MlKem768MlDsa65Aes256Gcm,
                CipherSuite::MlKem512MlDsa44Aes256Gcm,
            ],
            SecurityLevel::Level5 => vec![
                CipherSuite::MlKem1024MlDsa87Aes256Gcm,
                CipherSuite::MlKem768MlDsa65Aes256Gcm,
                CipherSuite::MlKem512MlDsa44Aes256Gcm,
            ],
        }
    }

    /// Get the name of this security level
    pub fn name(&self) -> &'static str {
        match self {
            SecurityLevel::Level1 => "Level 1 (AES-128 equivalent)",
            SecurityLevel::Level3 => "Level 3 (AES-192 equivalent)",
            SecurityLevel::Level5 => "Level 5 (AES-256 equivalent)",
        }
    }

    /// Get expected performance characteristics
    pub fn performance_notes(&self) -> &'static str {
        match self {
            SecurityLevel::Level1 => "Fastest, smallest keys (~20% faster than Level 3)",
            SecurityLevel::Level3 => "Balanced performance and security (recommended)",
            SecurityLevel::Level5 => "Highest security, largest keys (~20% slower than Level 3)",
        }
    }
}

impl Default for SecurityLevel {
    fn default() -> Self {
        SecurityLevel::Level3
    }
}

/// Key size information for each security level
pub struct KeySizes {
    pub encapsulation_key: usize,
    pub decapsulation_key: usize,
    pub ciphertext: usize,
    pub signing_key: usize,
    pub verifying_key: usize,
    pub signature: usize,
}

impl SecurityLevel {
    pub fn key_sizes(&self) -> KeySizes {
        match self {
            SecurityLevel::Level1 => KeySizes {
                encapsulation_key: 800,
                decapsulation_key: 1632,
                ciphertext: 768,
                signing_key: 2560,
                verifying_key: 1312,
                signature: 2420,
            },
            SecurityLevel::Level3 => KeySizes {
                encapsulation_key: 1184,
                decapsulation_key: 2400,
                ciphertext: 1088,
                signing_key: 4032,
                verifying_key: 1952,
                signature: 3309,
            },
            SecurityLevel::Level5 => KeySizes {
                encapsulation_key: 1568,
                decapsulation_key: 3168,
                ciphertext: 1568,
                signing_key: 4896,
                verifying_key: 2592,
                signature: 4627,
            },
        }
    }

    /// Total handshake size estimate
    pub fn estimated_handshake_size(&self) -> usize {
        let sizes = self.key_sizes();
        // ClientHello + ServerHello + Certificate + CertificateVerify + Finished
        sizes.encapsulation_key + sizes.ciphertext + sizes.verifying_key + sizes.signature + 500
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_levels() {
        assert_eq!(SecurityLevel::default(), SecurityLevel::Level3);
        assert_eq!(
            SecurityLevel::Level1.cipher_suite(),
            CipherSuite::MlKem512MlDsa44Aes256Gcm
        );
        assert_eq!(
            SecurityLevel::Level3.cipher_suite(),
            CipherSuite::MlKem768MlDsa65Aes256Gcm
        );
        assert_eq!(
            SecurityLevel::Level5.cipher_suite(),
            CipherSuite::MlKem1024MlDsa87Aes256Gcm
        );
    }

    #[test]
    fn test_supported_cipher_suites() {
        assert_eq!(SecurityLevel::Level1.supported_cipher_suites().len(), 1);
        assert_eq!(SecurityLevel::Level3.supported_cipher_suites().len(), 2);
        assert_eq!(SecurityLevel::Level5.supported_cipher_suites().len(), 3);
    }
}
