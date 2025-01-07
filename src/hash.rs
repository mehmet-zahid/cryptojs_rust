use sha2::{Sha256, Sha384, Sha512, Digest};
use crate::{CryptoError, Result};

pub trait Hash {
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Vec<u8>;
}

pub struct SHA256(Sha256);
pub struct SHA384(Sha384);
pub struct SHA512(Sha512);

impl SHA256 {
    pub fn new() -> Self {
        Self(Sha256::new())
    }
}

impl Hash for SHA256 {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> Vec<u8> {
        self.0.finalize().to_vec()
    }
}

impl SHA384 {
    pub fn new() -> Self {
        Self(Sha384::new())
    }
}

impl Hash for SHA384 {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> Vec<u8> {
        self.0.finalize().to_vec()
    }
}

impl SHA512 {
    pub fn new() -> Self {
        Self(Sha512::new())
    }
}

impl Hash for SHA512 {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> Vec<u8> {
        self.0.finalize().to_vec()
    }
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = SHA256::new();
    hasher.update(data);
    hasher.finalize()
}

pub fn sha384(data: &[u8]) -> Vec<u8> {
    let mut hasher = SHA384::new();
    hasher.update(data);
    hasher.finalize()
}

pub fn sha512(data: &[u8]) -> Vec<u8> {
    let mut hasher = SHA512::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::hex;

    #[test]
    fn test_sha256() {
        let data = b"Hello, World!";
        let hash = sha256(data);
        assert_eq!(
            hex::encode(&hash),
            "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        );
    }

    #[test]
    fn test_sha512() {
        let data = b"Hello, World!";
        let hash = sha512(data);
        assert_eq!(
            hex::encode(&hash),
            "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387"
        );
    }
} 