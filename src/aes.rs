use aes::{Aes128, Aes256};
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::{RngCore, thread_rng};

use crate::{CryptoError, Result, Mode, CryptoOperation};

const IV_SIZE: usize = 16;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub struct AesEncryptor {
    key_size: usize,
    mode: Mode,
    buffer: Vec<u8>,
    key: Vec<u8>,
    iv: Option<Vec<u8>>,
}

impl AesEncryptor {
    pub fn new_128(key: &[u8], mode: Mode) -> Result<Self> {
        Self::new(key, mode, 16)
    }

    pub fn new_256(key: &[u8], mode: Mode) -> Result<Self> {
        Self::new(key, mode, 32)
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
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let data = b"Hello, CryptoJS!";

        // Encrypt
        let mut encryptor = AesEncryptor::new_256(&key, Mode::CBC).unwrap();
        encryptor.update(data).unwrap();
        let encrypted = encryptor.finalize().unwrap();

        // Get IV from the first IV_SIZE bytes
        let iv = &encrypted[..IV_SIZE];
        
        // Decrypt
        let mut decryptor = AesDecryptor::new_256(&key, Mode::CBC, Some(iv)).unwrap();
        decryptor.update(&encrypted[IV_SIZE..]).unwrap();
        let decrypted = decryptor.finalize().unwrap();

        assert_eq!(data, &decrypted[..]);
    }
} 