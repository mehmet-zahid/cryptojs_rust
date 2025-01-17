const CryptoJS = require('crypto-js');

const message = "Hello, World!";
const password = "test123";

// Encrypt
const encrypted = CryptoJS.AES.encrypt(message, password).toString();
console.log('Encrypted:', encrypted);

// Verify decryption
const decrypted = CryptoJS.AES.decrypt(encrypted, password).toString(CryptoJS.enc.Utf8);
console.log('Decrypted:', decrypted); 