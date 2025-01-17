const CryptoJS = require('crypto-js');

// To decrypt data encrypted by Rust
function decryptFromRust(encryptedBase64, password) {
    console.log('Base64 input:', encryptedBase64);
    
    // Decode base64
    const encryptedBytes = Buffer.from(encryptedBase64, 'base64');
    console.log('Decoded bytes length:', encryptedBytes.length);
    
    // Extract IV (first 16 bytes) and ciphertext
    const iv = encryptedBytes.slice(0, 16);
    const ciphertext = encryptedBytes.slice(16);
    
    console.log('IV length:', iv.length);
    console.log('IV bytes:', Buffer.from(iv).toString('hex'));
    console.log('Ciphertext length:', ciphertext.length);
    
    // Convert to CryptoJS format
    const ciphertextWA = CryptoJS.lib.WordArray.create(ciphertext);
    const ivWA = CryptoJS.lib.WordArray.create(iv);
    
    // Create key directly from the 32-byte key string, ensuring exactly 32 bytes
    const keyBytes = Buffer.alloc(32); // Create a 32-byte buffer
    Buffer.from(password).copy(keyBytes, 0, 0, 32); // Copy only first 32 bytes
    console.log('Key length:', keyBytes.length);
    console.log('Key bytes:', keyBytes.toString('hex'));
    const key = CryptoJS.lib.WordArray.create(keyBytes);
    
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
const password = "12345678901234567890123456789012";

// Decrypt data from Rust
const decrypted = decryptFromRust(encrypted, password);
console.log("Decrypted:", decrypted);