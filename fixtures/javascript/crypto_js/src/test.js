// crypto-js library usage examples
const CryptoJS = require('crypto-js');

// AES encryption
function encryptAes(plaintext, key) {
    return CryptoJS.AES.encrypt(plaintext, key).toString();
}

// AES decryption
function decryptAes(ciphertext, key) {
    const bytes = CryptoJS.AES.decrypt(ciphertext, key);
    return bytes.toString(CryptoJS.enc.Utf8);
}

// SHA-256 hashing
function hashSha256(data) {
    return CryptoJS.SHA256(data).toString();
}

// SHA-512 hashing
function hashSha512(data) {
    return CryptoJS.SHA512(data).toString();
}

// MD5 hashing (not recommended for security)
function hashMd5(data) {
    return CryptoJS.MD5(data).toString();
}

// HMAC-SHA256
function hmacSha256(data, key) {
    return CryptoJS.HmacSHA256(data, key).toString();
}

// HMAC-SHA512
function hmacSha512(data, key) {
    return CryptoJS.HmacSHA512(data, key).toString();
}

// PBKDF2 key derivation
function deriveKey(password, salt) {
    return CryptoJS.PBKDF2(password, salt, {
        keySize: 256 / 32,
        iterations: 100000
    }).toString();
}

// Triple DES encryption (legacy)
function encryptTripleDes(plaintext, key) {
    return CryptoJS.TripleDES.encrypt(plaintext, key).toString();
}

// SHA-3 hashing
function hashSha3(data) {
    return CryptoJS.SHA3(data).toString();
}

module.exports = {
    encryptAes,
    decryptAes,
    hashSha256,
    hashSha512,
    hashMd5,
    hmacSha256,
    hmacSha512,
    deriveKey,
    encryptTripleDes,
    hashSha3
};
