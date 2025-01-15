# cryptojs_rust

A Rust implementation of CryptoJS encryption/decryption functionality, focusing on AES encryption compatibility.

## Features

- AES-256 encryption/decryption compatible with CryptoJS
- Support for various block cipher modes (CBC, ECB, CFB, OFB, CTR)
- CryptoJS-compatible key derivation
- Base64 encoding/decoding
- Proper PKCS7 padding handling

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
cryptojs_rust = "0.1.2"
```

## Usage

Here's a simple example of decrypting CryptoJS encrypted data:

```rust
use cryptojs_rust::cryptojs;

fn main() {
    let encrypted_data = "U2FsdGVkX1...";
    let password = "xxxxxxx";

    let decrypted = cryptojs::decrypt(&encrypted_data, password.as_bytes());
    println!("Decrypted: {:?}", decrypted);
}

```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Security

This crate implements cryptographic functionality. While we strive for correctness and security, this implementation has not been audited. Use at your own risk in production environments. 