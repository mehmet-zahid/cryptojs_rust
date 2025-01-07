use md5::{Md5, Digest};
use crate::{
    aes::AesDecryptor,
    utils::base64,
    Mode,
    Result,
    CryptoError,
    CryptoOperation,
};

/// Derives key and IV from password and salt using CryptoJS's key derivation method
pub fn derive_key_and_iv(password: &[u8], salt: &[u8]) -> ([u8; 32], [u8; 16]) {
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    
    // CryptoJS key derivation:
    let mut hasher = Md5::new();
    hasher.update(password);
    hasher.update(salt);
    let digest = hasher.finalize();
    
    key[..16].copy_from_slice(&digest);
    
    let mut hasher = Md5::new();
    hasher.update(&digest);
    hasher.update(password);
    hasher.update(salt);
    let digest = hasher.finalize();
    key[16..].copy_from_slice(&digest);
    
    let mut hasher = Md5::new();
    hasher.update(&digest);
    hasher.update(password);
    hasher.update(salt);
    let digest = hasher.finalize();
    iv.copy_from_slice(&digest);
    
    (key, iv)
}

/// Parses CryptoJS formatted encrypted data
pub fn parse_cryptojs_data(data: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let encrypted_data = base64::decode(data)
        .map_err(|_| CryptoError::InvalidData("Failed to decode base64".into()))?;
    
    if encrypted_data.len() < 16 || &encrypted_data[0..8] != b"Salted__" {
        return Err(CryptoError::InvalidData("Invalid CryptoJS format".into()));
    }
    
    let salt = encrypted_data[8..16].to_vec();
    let ciphertext = encrypted_data[16..].to_vec();
    
    Ok((salt, ciphertext))
}

/// Decrypts CryptoJS encrypted data with the given password
pub fn decrypt(encrypted_data: &str, password: &[u8]) -> Result<String> {
    // Parse CryptoJS format
    let (salt, ciphertext) = parse_cryptojs_data(encrypted_data)?;
    
    // Derive key and IV
    let (key, iv) = derive_key_and_iv(password, &salt);
    
    // Create decryptor and decrypt
    let mut decryptor = AesDecryptor::new_256(&key, Mode::CBC, Some(&iv))?;
    decryptor.update(&ciphertext)?;
    let decrypted = decryptor.finalize()?;
    
    // Remove PKCS7 padding
    let last_byte = decrypted.last()
        .ok_or_else(|| CryptoError::InvalidData("Empty decrypted data".into()))?;
    let padding_len = *last_byte as usize;
    
    let decrypted = if padding_len > 0 && padding_len <= 16 {
        &decrypted[..decrypted.len() - padding_len]
    } else {
        &decrypted
    };
    
    // Convert to string
    String::from_utf8(decrypted.to_vec())
        .map_err(|_| CryptoError::InvalidData("Invalid UTF-8".into()))
} 