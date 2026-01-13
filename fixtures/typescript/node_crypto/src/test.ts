// Node.js crypto module usage in TypeScript
import crypto from 'node:crypto';

interface EncryptedData {
    encrypted: string;
    iv: Buffer;
    authTag: Buffer;
}

interface KeyPair {
    publicKey: string;
    privateKey: string;
}

// SHA-256 hashing
export function hashData(data: string): string {
    const hash = crypto.createHash('sha256');
    hash.update(data);
    return hash.digest('hex');
}

// SHA-512 hashing
export function hashSha512(data: string): string {
    const hash = crypto.createHash('sha512');
    hash.update(data);
    return hash.digest('hex');
}

// HMAC-SHA256
export function hmacSign(data: string, key: Buffer): string {
    const hmac = crypto.createHmac('sha256', key);
    hmac.update(data);
    return hmac.digest('hex');
}

// AES-256-GCM encryption
export function encryptAesGcm(plaintext: string, key: Buffer): EncryptedData {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return { encrypted, iv, authTag };
}

// AES-256-GCM decryption
export function decryptAesGcm(
    encrypted: string,
    key: Buffer,
    iv: Buffer,
    authTag: Buffer
): string {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// AES-256-CBC encryption
export function encryptAesCbc(plaintext: string, key: Buffer, iv: Buffer): string {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Ed25519 key pair generation
export function generateEd25519KeyPair(): KeyPair {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    return { publicKey, privateKey };
}

// RSA key pair generation
export async function generateRsaKeyPair(): Promise<KeyPair> {
    return new Promise((resolve, reject) => {
        crypto.generateKeyPair('rsa', {
            modulusLength: 4096,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        }, (err, publicKey, privateKey) => {
            if (err) reject(err);
            else resolve({ publicKey, privateKey });
        });
    });
}

// ECDSA key pair generation
export function generateEcdsaKeyPair(): KeyPair {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'P-384',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    return { publicKey, privateKey };
}

// PBKDF2 key derivation
export function deriveKeyPbkdf2(password: string, salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
}

// scrypt key derivation
export function deriveKeyScrypt(password: string, salt: Buffer): Buffer {
    return crypto.scryptSync(password, salt, 32);
}

// HKDF key derivation
export function deriveKeyHkdf(
    ikm: Buffer,
    salt: Buffer,
    info: Buffer
): Buffer {
    return crypto.hkdfSync('sha256', ikm, salt, info, 32);
}

// ChaCha20-Poly1305 encryption
export function encryptChaCha20(plaintext: string, key: Buffer, iv: Buffer): EncryptedData {
    const cipher = crypto.createCipheriv('chacha20-poly1305', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return { encrypted, iv, authTag };
}
