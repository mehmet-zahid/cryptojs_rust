const CryptoJS = require('crypto-js');

// To decrypt data encrypted by Rust
function decryptFromRust(encryptedBase64, password) {
    console.log('Base64 input:', encryptedBase64);
    
    // Decode base64
    const encryptedBytes = Buffer.from(encryptedBase64, 'base64');
    console.log('Decoded bytes length:', encryptedBytes.length);
    
    // Extract salt (first 16 bytes), IV (next 16 bytes) and ciphertext
    const salt = encryptedBytes.subarray(0, 16);
    const iv = encryptedBytes.subarray(16, 32);
    const ciphertext = encryptedBytes.subarray(32);
    
    console.log('Salt length:', salt.length);
    console.log('Salt bytes:', Buffer.from(salt).toString('hex'));
    console.log('IV length:', iv.length);
    console.log('IV bytes:', Buffer.from(iv).toString('hex'));
    console.log('Ciphertext length:', ciphertext.length);
    
    // Convert to CryptoJS format
    const ciphertextWA = CryptoJS.lib.WordArray.create(ciphertext);
    const ivWA = CryptoJS.lib.WordArray.create(iv);
    const saltWA = CryptoJS.lib.WordArray.create(salt);
    
    // Create key using PBKDF2
    const key = CryptoJS.PBKDF2(password, saltWA, {
        keySize: 256/32,
        iterations: 10000,
        hasher: CryptoJS.algo.SHA256
    });
    
    try {
        // Decrypt
        const decrypted = CryptoJS.AES.decrypt(
            {
                ciphertext: ciphertextWA
            },
            key,
            {
                iv: ivWA,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            }
        );
        
        return decrypted.toString(CryptoJS.enc.Utf8);
    } catch (error) {
        console.error('Decryption error:', error);
        return '';
    }
}

// Example usage:
const fs = require('fs');
const encrypted = fs.readFileSync('test_encrypted.txt', 'utf8').trim(); // encrypted string from Rust
const password = "my secret password";

// Decrypt data from Rust
const decrypted = decryptFromRust(encrypted, password);
console.log("Decrypted:", decrypted);