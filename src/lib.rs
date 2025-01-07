pub mod aes;
pub mod hash;
pub mod utils;
pub mod cryptojs;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("encryption error: {0}")]
    EncryptionError(String),
    #[error("decryption error: {0}")]
    DecryptionError(String),
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("invalid input data: {0}")]
    InvalidInput(String),
    #[error("invalid data: {0}")]
    InvalidData(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// Represents the mode of operation for block ciphers
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Mode {
    CBC,
    ECB,
    CFB,
    OFB,
    CTR,
}

/// Common trait for all cryptographic operations
pub trait CryptoOperation {
    type Output;
    
    fn update(&mut self, data: &[u8]) -> Result<()>;
    fn finalize(self) -> Result<Self::Output>;
}

/// Trait for encryption operations
pub trait Encryptor: CryptoOperation {
    fn new(key: &[u8], iv: Option<&[u8]>) -> Result<Self> where Self: Sized;
}

/// Trait for decryption operations
pub trait Decryptor: CryptoOperation {
    fn new(key: &[u8], iv: Option<&[u8]>) -> Result<Self> where Self: Sized;
}

#[cfg(test)]
mod tests {
    //use super::*;

    // Add tests here as we implement features
} 