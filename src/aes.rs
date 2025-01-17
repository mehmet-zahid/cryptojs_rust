use aes::{Aes128, Aes256};
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::{RngCore, thread_rng};
use base64::engine::Engine;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

use crate::{CryptoError, Result, Mode, CryptoOperation};

const IV_SIZE: usize = 16;
const SALT_SIZE: usize = 16;
const ITERATIONS: u32 = 10000;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub struct AesEncryptor {
    key_size: usize,
    mode: Mode,
    buffer: Vec<u8>,
    key: Vec<u8>,
    iv: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
}

impl AesEncryptor {
    pub fn new_128(key: &[u8], mode: Mode) -> Result<Self> {
        Self::new(key, mode, 16)
    }

    pub fn new_256(key: &[u8], mode: Mode) -> Result<Self> {
        Self::new(key, mode, 32)
    }

    pub fn new_256_from_password(password: &[u8], mode: Mode) -> Result<Self> {
        let mut salt = vec![0u8; SALT_SIZE];
        thread_rng().fill_bytes(&mut salt);
        
        let mut key = vec![0u8; 32];
        pbkdf2_hmac::<Sha256>(password, &salt, ITERATIONS, &mut key);

        let mut iv = None;
        if mode == Mode::CBC {
            let mut iv_bytes = vec![0u8; IV_SIZE];
            thread_rng().fill_bytes(&mut iv_bytes);
            iv = Some(iv_bytes);
        }

        Ok(Self {
            key_size: 32,
            mode,
            buffer: Vec::new(),
            key,
            iv,
            salt: Some(salt),
        })
    }

    fn new(key: &[u8], mode: Mode, key_size: usize) -> Result<Self> {
        if key.len() != key_size {
            return Err(CryptoError::InvalidKeyLength);
        }

        let mut iv = None;
        if mode == Mode::CBC {
            let mut iv_bytes = vec![0u8; IV_SIZE];
            thread_rng().fill_bytes(&mut iv_bytes);
            iv = Some(iv_bytes);
        }

        Ok(Self {
            key_size,
            mode,
            buffer: Vec::new(),
            key: key.to_vec(),
            iv,
            salt: None,
        })
    }
}

impl CryptoOperation for AesEncryptor {
    type Output = Vec<u8>;

    fn update(&mut self, data: &[u8]) -> Result<()> {
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    fn finalize(self) -> Result<Self::Output> {
        match self.mode {
            Mode::CBC => {
                let iv = self.iv.ok_or_else(|| CryptoError::InvalidInput("IV required for CBC mode".into()))?;
                let mut output = Vec::new();
                
                // If we have a salt (password-based), include it in the output
                if let Some(salt) = self.salt {
                    output.extend_from_slice(&salt);
                }
                
                output.extend_from_slice(&iv);

                let ciphertext = match self.key_size {
                    16 => {
                        let cipher = Aes128Cbc::new_from_slices(&self.key, &iv)
                            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
                        cipher.encrypt_vec(&self.buffer)
                    },
                    32 => {
                        let cipher = Aes256Cbc::new_from_slices(&self.key, &iv)
                            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
                        cipher.encrypt_vec(&self.buffer)
                    },
                    _ => return Err(CryptoError::InvalidKeyLength),
                };

                output.extend_from_slice(&ciphertext);
                Ok(output)
            },
            _ => Err(CryptoError::InvalidInput("Mode not implemented yet".into())),
        }
    }
}

pub struct AesDecryptor {
    key_size: usize,
    mode: Mode,
    buffer: Vec<u8>,
    key: Vec<u8>,
    iv: Option<Vec<u8>>,
}

impl AesDecryptor {
    pub fn new_128(key: &[u8], mode: Mode, iv: Option<&[u8]>) -> Result<Self> {
        Self::new(key, mode, 16, iv)
    }

    pub fn new_256(key: &[u8], mode: Mode, iv: Option<&[u8]>) -> Result<Self> {
        Self::new(key, mode, 32, iv)
    }

    pub fn new_256_from_password(password: &[u8], mode: Mode, salt: &[u8], iv: Option<&[u8]>) -> Result<Self> {
        if salt.len() != SALT_SIZE {
            return Err(CryptoError::InvalidInput("Salt must be 16 bytes".into()));
        }

        let mut key = vec![0u8; 32];
        pbkdf2_hmac::<Sha256>(password, salt, ITERATIONS, &mut key);

        if let Some(iv) = iv {
            if iv.len() != IV_SIZE {
                return Err(CryptoError::InvalidInput("IV must be 16 bytes".into()));
            }
        }

        let iv = iv.map(|v| v.to_vec());

        Ok(Self {
            key_size: 32,
            mode,
            buffer: Vec::new(),
            key,
            iv,
        })
    }

    fn new(key: &[u8], mode: Mode, key_size: usize, iv: Option<&[u8]>) -> Result<Self> {
        if key.len() != key_size {
            return Err(CryptoError::InvalidKeyLength);
        }

        if let Some(iv) = iv {
            if iv.len() != IV_SIZE {
                return Err(CryptoError::InvalidInput("IV must be 16 bytes".into()));
            }
        }

        let iv = iv.map(|v| v.to_vec());

        Ok(Self {
            key_size,
            mode,
            buffer: Vec::new(),
            key: key.to_vec(),
            iv,
        })
    }
}

impl CryptoOperation for AesDecryptor {
    type Output = Vec<u8>;

    fn update(&mut self, data: &[u8]) -> Result<()> {
        self.buffer.extend_from_slice(data);
        Ok(())
    }

    fn finalize(self) -> Result<Self::Output> {
        match self.mode {
            Mode::CBC => {
                let iv = self.iv.ok_or_else(|| CryptoError::InvalidInput("IV required for CBC mode".into()))?;
                match self.key_size {
                    16 => {
                        let cipher = Aes128Cbc::new_from_slices(&self.key, &iv)
                            .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
                        cipher.decrypt_vec(&self.buffer)
                            .map_err(|e| CryptoError::DecryptionError(e.to_string()))
                    },
                    32 => {
                        let cipher = Aes256Cbc::new_from_slices(&self.key, &iv)
                            .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
                        cipher.decrypt_vec(&self.buffer)
                            .map_err(|e| CryptoError::DecryptionError(e.to_string()))
                    },
                    _ => Err(CryptoError::InvalidKeyLength),
                }
            },
            _ => Err(CryptoError::InvalidInput("Mode not implemented yet".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::hex;

    #[test]
    fn test_aes_256_cbc() {
        // Use exact 32-byte key
        let key = b"12345678901234567890123456789012";
        assert_eq!(key.len(), 32, "Key must be exactly 32 bytes");
        
        let data = b"Hello, CryptoJS!";

        // Encrypt
        let mut encryptor = AesEncryptor::new_256(key, Mode::CBC).unwrap();
        encryptor.update(data).unwrap();
        let encrypted = encryptor.finalize().unwrap();
        
        // Print debug info
        println!("IV (hex): {:?}", hex::encode(&encrypted[..IV_SIZE]));
        println!("Ciphertext (hex): {:?}", hex::encode(&encrypted[IV_SIZE..]));
        
        // Save encrypted data to file for testing with Node.js
        use std::fs::write;
        write("test_encrypted.txt", base64::engine::general_purpose::STANDARD.encode(&encrypted)).unwrap();

        // Get IV from the first IV_SIZE bytes
        let iv = &encrypted[..IV_SIZE];
        
        // Decrypt
        let mut decryptor = AesDecryptor::new_256(key, Mode::CBC, Some(iv)).unwrap();
        decryptor.update(&encrypted[IV_SIZE..]).unwrap();
        let decrypted = decryptor.finalize().unwrap();

        assert_eq!(data, &decrypted[..]);
    }

    #[test]
    fn test_aes_256_cbc_with_password() {
        let password = b"my secret password";
        let data = b"Hello, CryptoJS!";

        // Encrypt
        let mut encryptor = AesEncryptor::new_256_from_password(password, Mode::CBC).unwrap();
        encryptor.update(data).unwrap();
        let encrypted = encryptor.finalize().unwrap();
        
        // First SALT_SIZE bytes are salt, next IV_SIZE bytes are IV
        let salt = &encrypted[..SALT_SIZE];
        let iv = &encrypted[SALT_SIZE..SALT_SIZE + IV_SIZE];
        let ciphertext = &encrypted[SALT_SIZE + IV_SIZE..];
        
        // Print debug info
        println!("Salt (hex): {:?}", hex::encode(salt));
        println!("IV (hex): {:?}", hex::encode(iv));
        println!("Ciphertext (hex): {:?}", hex::encode(ciphertext));
        
        // Save encrypted data to file for testing with Node.js
        use std::fs::write;
        write("test_encrypted.txt", base64::engine::general_purpose::STANDARD.encode(&encrypted)).unwrap();

        // Decrypt
        let mut decryptor = AesDecryptor::new_256_from_password(password, Mode::CBC, salt, Some(iv)).unwrap();
        decryptor.update(ciphertext).unwrap();
        let decrypted = decryptor.finalize().unwrap();

        assert_eq!(data, &decrypted[..]);
    }
} 