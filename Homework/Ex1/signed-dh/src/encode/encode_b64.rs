use base64::{engine::general_purpose::STANDARD, Engine};

/// Encode bytes as Base64
pub fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Decode Base64 to bytes
pub fn from_b64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(s)
}
