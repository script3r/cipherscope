// Node.js crypto module usage examples
const crypto = require('crypto');

// SHA-256 hashing
function hashData(data) {
    const hash = crypto.createHash('sha256');
    hash.update(data);
    return hash.digest('hex');
}

// HMAC-SHA256
function hmacSign(data, key) {
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(data);
    return hmac.digest('hex');
}

// AES-256-GCM encryption
function encryptAesGcm(plaintext, key) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return { encrypted, iv, authTag };
}

// AES-256-GCM decryption
function decryptAesGcm(encrypted, key, iv, authTag) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// RSA key pair generation
async function generateRsaKeyPair() {
    return new Promise((resolve, reject) => {
        crypto.generateKeyPair('rsa', {
            modulusLength: 4096,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        }, (err, publicKey, privateKey) => {
            if (err) reject(err);
            else resolve({ publicKey, privateKey });
        });
    });
}

// PBKDF2 key derivation
function deriveKey(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
}

// scrypt key derivation
function deriveKeyScrypt(password, salt) {
    return crypto.scryptSync(password, salt, 32);
}

module.exports = {
    hashData,
    hmacSign,
    encryptAesGcm,
    decryptAesGcm,
    generateRsaKeyPair,
    deriveKey,
    deriveKeyScrypt
};
