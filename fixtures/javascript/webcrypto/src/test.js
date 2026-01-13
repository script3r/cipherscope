// Web Crypto API usage examples
async function generateAesKey() {
    return await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
}

async function encryptData(key, data) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(data);
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        encoded
    );
    return { ciphertext, iv };
}

async function decryptData(key, ciphertext, iv) {
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext
    );
    return new TextDecoder().decode(decrypted);
}

async function generateRsaKeyPair() {
    return await crypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 4096,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        true,
        ['encrypt', 'decrypt']
    );
}

async function generateEcdsaKeyPair() {
    return await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-384' },
        true,
        ['sign', 'verify']
    );
}

async function signData(privateKey, data) {
    const encoded = new TextEncoder().encode(data);
    return await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-384' },
        privateKey,
        encoded
    );
}

async function verifySignature(publicKey, signature, data) {
    const encoded = new TextEncoder().encode(data);
    return await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-384' },
        publicKey,
        signature,
        encoded
    );
}

async function hashSha256(data) {
    const encoded = new TextEncoder().encode(data);
    return await crypto.subtle.digest('SHA-256', encoded);
}

async function deriveKeyPbkdf2(password, salt) {
    const encoded = new TextEncoder().encode(password);
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoded,
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    );
    return await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
}

export {
    generateAesKey,
    encryptData,
    decryptData,
    generateRsaKeyPair,
    generateEcdsaKeyPair,
    signData,
    verifySignature,
    hashSha256,
    deriveKeyPbkdf2
};
