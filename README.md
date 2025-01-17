# cryptojs_rust

A Rust implementation of CryptoJS encryption/decryption functionality, focusing on AES encryption compatibility.

## Features

- AES-256 and AES-128 encryption/decryption compatible with CryptoJS
- Password-based key derivation using PBKDF2-HMAC-SHA256
- Support for CBC mode encryption (more modes coming soon)
- CryptoJS-compatible key derivation with salt
- Base64 encoding/decoding
- Proper PKCS7 padding handling

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
cryptojs_rust = "0.1.3"
```

## Usage Examples

### Decrypting data from CryptoJS (Simple example)

```rs
use cryptojs_rust::cryptojs;

fn main() {
    let encrypted_data = "U2FsdGVkX1...";
    let password = "xxxxxxx";

    let decrypted = cryptojs::decrypt(&encrypted_data, password.as_bytes());
    println!("Decrypted: {:?}", decrypted);
}
```

### Password-Based Encryption (Recommended)

This is the most common and secure way to use the library, as it properly handles key derivation from passwords:

```rust
use cryptojs_rust::{Mode, AesEncryptor, AesDecryptor, CryptoOperation};

// Encryption
let password = b"my secret password";
let data = b"Hello, CryptoJS!";

// Create an encryptor with password
let mut encryptor = AesEncryptor::new_256_from_password(password, Mode::CBC).unwrap();
encryptor.update(data).unwrap();
let encrypted = encryptor.finalize().unwrap();

// The encrypted output contains: [16 bytes salt][16 bytes IV][ciphertext]
let salt = &encrypted[..16];
let iv = &encrypted[16..32];
let ciphertext = &encrypted[32..];

// Decryption
let mut decryptor = AesDecryptor::new_256_from_password(
    password,
    Mode::CBC,
    salt,
    Some(iv)
).unwrap();
decryptor.update(ciphertext).unwrap();
let decrypted = decryptor.finalize().unwrap();

assert_eq!(data, &decrypted[..]);
```

### Raw Key Encryption

If you already have a proper-length key (32 bytes for AES-256, 16 bytes for AES-128):

```rust
use cryptojs_rust::{Mode, AesEncryptor, AesDecryptor, CryptoOperation};

// Use exact 32-byte key for AES-256
let key = b"12345678901234567890123456789012";
let data = b"Hello, CryptoJS!";

// Encrypt
let mut encryptor = AesEncryptor::new_256(key, Mode::CBC).unwrap();
encryptor.update(data).unwrap();
let encrypted = encryptor.finalize().unwrap();

// The encrypted output contains: [16 bytes IV][ciphertext]
let iv = &encrypted[..16];
let ciphertext = &encrypted[16..];

// Decrypt
let mut decryptor = AesDecryptor::new_256(key, Mode::CBC, Some(iv)).unwrap();
decryptor.update(ciphertext).unwrap();
let decrypted = decryptor.finalize().unwrap();

assert_eq!(data, &decrypted[..]);
```

### Working with Base64

When exchanging encrypted data, it's common to use base64 encoding:

```rust
use base64::{Engine, engine::general_purpose::STANDARD};
use cryptojs_rust::{Mode, AesEncryptor, CryptoOperation};

// Encrypt and base64 encode
let mut encryptor = AesEncryptor::new_256_from_password(b"password", Mode::CBC).unwrap();
encryptor.update(b"secret data").unwrap();
let encrypted = encryptor.finalize().unwrap();
let base64_data = STANDARD.encode(&encrypted);

// Now base64_data can be safely transmitted or stored
println!("Encrypted (base64): {}", base64_data);
```

## Compatibility with CryptoJS

The library is designed to be compatible with CryptoJS's AES encryption. When using password-based encryption:

1. The key is derived using PBKDF2-HMAC-SHA256 with 10,000 iterations
2. A random 16-byte salt is generated for each encryption
3. A random 16-byte IV is used for CBC mode
4. The output format is: `[salt (16 bytes)][iv (16 bytes)][ciphertext]`
5. The final output is typically base64 encoded for storage or transmission

## Security Considerations

- Always use password-based encryption (`new_256_from_password`) unless you have a specific reason to use raw keys
- The raw key methods (`new_256`, `new_128`) should only be used when you have proper key generation and management
- The library uses secure defaults:
  - PBKDF2-HMAC-SHA256 with 10,000 iterations for key derivation
  - Random salt for each encryption
  - Random IV for each encryption
  - CBC mode with PKCS7 padding

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Security

This crate implements cryptographic functionality. While we strive for correctness and security, this implementation has not been audited. Use at your own risk in production environments. 