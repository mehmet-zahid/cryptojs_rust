use cryptojs_rust::{
    aes::{AesEncryptor, AesDecryptor},
    hash::{sha256, SHA256, Hash},
    utils::{base64, hex},
    Mode, CryptoOperation,
    cryptojs,
};

#[test]
fn test_aes_128_encryption_decryption() {
    // 16-byte key for AES-128
    let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let data = b"Hello, CryptoJS! This is a test message for AES-128.";

    // Encrypt
    let mut encryptor = AesEncryptor::new_128(&key, Mode::CBC).unwrap();
    encryptor.update(data).unwrap();
    let encrypted = encryptor.finalize().unwrap();

    // Get IV from the first 16 bytes
    let iv = &encrypted[..16];
    
    // Decrypt
    let mut decryptor = AesDecryptor::new_128(&key, Mode::CBC, Some(iv)).unwrap();
    decryptor.update(&encrypted[16..]).unwrap();
    let decrypted = decryptor.finalize().unwrap();

    assert_eq!(data, &decrypted[..]);
}

#[test]
fn test_aes_256_encryption_decryption() {
    // 32-byte key for AES-256
    let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let data = b"Hello, CryptoJS! This is a test message for AES-256.";

    // Encrypt
    let mut encryptor = AesEncryptor::new_256(&key, Mode::CBC).unwrap();
    encryptor.update(data).unwrap();
    let encrypted = encryptor.finalize().unwrap();

    // Get IV from the first 16 bytes
    let iv = &encrypted[..16];
    
    // Decrypt
    let mut decryptor = AesDecryptor::new_256(&key, Mode::CBC, Some(iv)).unwrap();
    decryptor.update(&encrypted[16..]).unwrap();
    let decrypted = decryptor.finalize().unwrap();

    assert_eq!(data, &decrypted[..]);
}

#[test]
fn test_streaming_encryption() {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let data1 = b"Hello, ";
    let data2 = b"CryptoJS! ";
    let data3 = b"This is a streaming test.";

    // Encrypt in chunks
    let mut encryptor = AesEncryptor::new_256(&key, Mode::CBC).unwrap();
    encryptor.update(data1).unwrap();
    encryptor.update(data2).unwrap();
    encryptor.update(data3).unwrap();
    let encrypted = encryptor.finalize().unwrap();

    // Get IV from the first 16 bytes
    let iv = &encrypted[..16];
    
    // Decrypt
    let mut decryptor = AesDecryptor::new_256(&key, Mode::CBC, Some(iv)).unwrap();
    decryptor.update(&encrypted[16..]).unwrap();
    let decrypted = decryptor.finalize().unwrap();

    let mut expected = Vec::new();
    expected.extend_from_slice(data1);
    expected.extend_from_slice(data2);
    expected.extend_from_slice(data3);
    assert_eq!(&expected[..], &decrypted[..]);
}

#[test]
fn test_hash_functions() {
    let data = b"Hello, World!";
    
    // Test one-shot hashing
    let sha256_hash = sha256(data);

    assert_eq!(
        hex::encode(&sha256_hash),
        "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
    );

    // Test streaming hashing
    let mut hasher = SHA256::new();
    hasher.update(b"Hello, ");
    hasher.update(b"World!");
    let streaming_hash = hasher.finalize();

    assert_eq!(sha256_hash, streaming_hash);
}

#[test]
fn test_encodings() {
    let data = b"Hello, CryptoJS!";

    // Test hex encoding/decoding
    let hex_encoded = hex::encode(data);
    let hex_decoded = hex::decode(&hex_encoded).unwrap();
    assert_eq!(data, &hex_decoded[..]);

    // Test base64 encoding/decoding
    let base64_encoded = base64::encode(data);
    let base64_decoded = base64::decode(&base64_encoded).unwrap();
    assert_eq!(data, &base64_decoded[..]);
}

#[test]
fn test_invalid_key_sizes() {
    // Try to use wrong key size for AES-128
    let invalid_key = hex::decode("0001020304").unwrap(); // 5 bytes instead of 16
    assert!(AesEncryptor::new_128(&invalid_key, Mode::CBC).is_err());

    // Try to use wrong key size for AES-256
    let invalid_key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap(); // 16 bytes instead of 32
    assert!(AesEncryptor::new_256(&invalid_key, Mode::CBC).is_err());
}

#[test]
fn test_decryption_with_wrong_key() {
    let key1 = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let key2 = hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
    let data = b"Hello, CryptoJS!";

    // Encrypt with key1
    let mut encryptor = AesEncryptor::new_256(&key1, Mode::CBC).unwrap();
    encryptor.update(data).unwrap();
    let encrypted = encryptor.finalize().unwrap();

    // Try to decrypt with key2
    let iv = &encrypted[..16];
    let mut decryptor = AesDecryptor::new_256(&key2, Mode::CBC, Some(iv)).unwrap();
    decryptor.update(&encrypted[16..]).unwrap();
    assert!(decryptor.finalize().is_err()); // Should fail
}

#[test]
fn test_cryptojs_decrypt() {
    // This is a CryptoJS-encrypted string containing "Hello, World!" encrypted with password "test123"
    // Generated using CryptoJS.AES.encrypt()
    let encrypted = "U2FsdGVkX18QdIkEG8mOikjNEarOv1P91J6m2+BsgLE=";
    let password = b"test123";
    
    let decrypted = cryptojs::decrypt(encrypted, password).unwrap();
    assert_eq!(decrypted, "Hello, World!");
    
    // Test invalid data format
    let invalid_data = "InvalidBase64Data";
    assert!(cryptojs::decrypt(invalid_data, password).is_err());
    
    // Test invalid password
    let wrong_password = b"wrongpass";
    assert!(cryptojs::decrypt(encrypted, wrong_password).is_err());
} 