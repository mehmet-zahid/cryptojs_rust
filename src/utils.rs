pub mod hex {
    use crate::CryptoError;

    pub fn encode(data: &[u8]) -> String {
        hex::encode(data)
    }

    pub fn decode(hex_str: &str) -> Result<Vec<u8>, CryptoError> {
        hex::decode(hex_str)
            .map_err(|e| CryptoError::InvalidInput(format!("Invalid hex string: {}", e)))
    }
}

pub mod base64 {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use crate::CryptoError;

    pub fn encode(data: &[u8]) -> String {
        STANDARD.encode(data)
    }

    pub fn decode(data: &str) -> Result<Vec<u8>, CryptoError> {
        STANDARD.decode(data)
            .map_err(|e| CryptoError::InvalidInput(format!("Invalid base64 string: {}", e)))
    }
} 