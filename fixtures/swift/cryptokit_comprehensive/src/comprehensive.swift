import Foundation
import CryptoKit

func testSymmetricCiphers() throws {
    let key256 = SymmetricKey(size: .bits256)
    let key192 = SymmetricKey(size: .bits192)
    let key128 = SymmetricKey(size: .bits128)
    let nonce = AES.GCM.Nonce()
    let plaintext = "Hello, World!".data(using: .utf8)!
    
    // AES-GCM
    let sealedBoxAES = try AES.GCM.seal(plaintext, using: key256, nonce: nonce)
    let decryptedAES = try AES.GCM.open(sealedBoxAES, using: key256)
    
    // AES-GCM with different key sizes
    let sealedBox128 = try AES.GCM.seal(plaintext, using: key128)
    let sealedBox192 = try AES.GCM.seal(plaintext, using: key192)
    
    // ChaCha20-Poly1305
    let chachaKey = SymmetricKey(size: .bits256)
    let chachaNonce = ChaChaPoly.Nonce()
    let sealedBoxChaCha = try ChaChaPoly.seal(plaintext, using: chachaKey, nonce: chachaNonce)
    let decryptedChaCha = try ChaChaPoly.open(sealedBoxChaCha, using: chachaKey)
    
    // Additional ChaCha20-Poly1305 operations
    let sealedBoxChaCha2 = try ChaChaPoly.seal(plaintext, using: chachaKey)
}

func testAsymmetricAlgorithms() throws {
    // Curve25519 - X25519 key agreement
    let privateKeyX25519 = Curve25519.KeyAgreement.PrivateKey()
    let publicKeyX25519 = privateKeyX25519.publicKey
    
    let otherPrivateKeyX25519 = Curve25519.KeyAgreement.PrivateKey()
    let otherPublicKeyX25519 = otherPrivateKeyX25519.publicKey
    
    let sharedSecretX25519 = try privateKeyX25519.sharedSecretFromKeyAgreement(with: otherPublicKeyX25519)
    let symmetricKeyX25519 = sharedSecretX25519.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: Data(),
        sharedInfo: Data(),
        outputByteCount: 32
    )
    
    // Curve25519 - Ed25519 signing
    let signingKeyEd25519 = Curve25519.Signing.PrivateKey()
    let signingPublicKeyEd25519 = signingKeyEd25519.publicKey
    let dataToSign = "Message to sign".data(using: .utf8)!
    let signatureEd25519 = try signingKeyEd25519.signature(for: dataToSign)
    let isValidEd25519 = signingPublicKeyEd25519.isValidSignature(signatureEd25519, for: dataToSign)
    
    // P256 (NIST P-256)
    let privateKeyP256 = P256.KeyAgreement.PrivateKey()
    let publicKeyP256 = privateKeyP256.publicKey
    
    let otherPrivateKeyP256 = P256.KeyAgreement.PrivateKey()
    let otherPublicKeyP256 = otherPrivateKeyP256.publicKey
    
    let sharedSecretP256 = try privateKeyP256.sharedSecretFromKeyAgreement(with: otherPublicKeyP256)
    let symmetricKeyP256 = sharedSecretP256.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: Data(),
        sharedInfo: Data(),
        outputByteCount: 32
    )
    
    // P384 (NIST P-384)
    let privateKeyP384 = P384.KeyAgreement.PrivateKey()
    let publicKeyP384 = privateKeyP384.publicKey
    
    let otherPrivateKeyP384 = P384.KeyAgreement.PrivateKey()
    let otherPublicKeyP384 = otherPrivateKeyP384.publicKey
    
    let sharedSecretP384 = try privateKeyP384.sharedSecretFromKeyAgreement(with: otherPublicKeyP384)
    let symmetricKeyP384 = sharedSecretP384.hkdfDerivedSymmetricKey(
        using: SHA384.self,
        salt: Data(),
        sharedInfo: Data(),
        outputByteCount: 48
    )
    
    // P521 (NIST P-521)
    let privateKeyP521 = P521.KeyAgreement.PrivateKey()
    let publicKeyP521 = privateKeyP521.publicKey
    
    let otherPrivateKeyP521 = P521.KeyAgreement.PrivateKey()
    let otherPublicKeyP521 = otherPrivateKeyP521.publicKey
    
    let sharedSecretP521 = try privateKeyP521.sharedSecretFromKeyAgreement(with: otherPublicKeyP521)
    let symmetricKeyP521 = sharedSecretP521.hkdfDerivedSymmetricKey(
        using: SHA512.self,
        salt: Data(),
        sharedInfo: Data(),
        outputByteCount: 64
    )
}

func testSignatureAlgorithms() throws {
    let dataToSign = "Message to sign".data(using: .utf8)!
    
    // Ed25519 signatures
    let ed25519SigningKey = Curve25519.Signing.PrivateKey()
    let ed25519PublicKey = ed25519SigningKey.publicKey
    let ed25519Signature = try ed25519SigningKey.signature(for: dataToSign)
    let ed25519Valid = ed25519PublicKey.isValidSignature(ed25519Signature, for: dataToSign)
    
    // ECDSA with P256
    let p256SigningKey = P256.Signing.PrivateKey()
    let p256PublicKey = p256SigningKey.publicKey
    let p256Signature = try p256SigningKey.signature(for: dataToSign)
    let p256Valid = p256PublicKey.isValidSignature(p256Signature, for: dataToSign)
    
    // ECDSA with P384
    let p384SigningKey = P384.Signing.PrivateKey()
    let p384PublicKey = p384SigningKey.publicKey
    let p384Signature = try p384SigningKey.signature(for: dataToSign)
    let p384Valid = p384PublicKey.isValidSignature(p384Signature, for: dataToSign)
    
    // ECDSA with P521
    let p521SigningKey = P521.Signing.PrivateKey()
    let p521PublicKey = p521SigningKey.publicKey
    let p521Signature = try p521SigningKey.signature(for: dataToSign)
    let p521Valid = p521PublicKey.isValidSignature(p521Signature, for: dataToSign)
}

func testHashAlgorithms() {
    let data = "Data to hash".data(using: .utf8)!
    
    // SHA-256
    let hashSHA256 = SHA256.hash(data: data)
    let digestSHA256 = hashSHA256.compactMap { String(format: "%02x", $0) }.joined()
    
    // SHA-384
    let hashSHA384 = SHA384.hash(data: data)
    let digestSHA384 = hashSHA384.compactMap { String(format: "%02x", $0) }.joined()
    
    // SHA-512
    let hashSHA512 = SHA512.hash(data: data)
    let digestSHA512 = hashSHA512.compactMap { String(format: "%02x", $0) }.joined()
    
    // SHA-1 (Insecure)
    let hashSHA1 = Insecure.SHA1.hash(data: data)
    let digestSHA1 = hashSHA1.compactMap { String(format: "%02x", $0) }.joined()
    
    // MD5 (Insecure)
    let hashMD5 = Insecure.MD5.hash(data: data)
    let digestMD5 = hashMD5.compactMap { String(format: "%02x", $0) }.joined()
    
    // Note: SHA-224, SHA3 variants are not directly available in CryptoKit
    // SHA3 would require iOS 16.0+ / macOS 13.0+
    
    // Additional hash operations with incremental updates
    var hasherSHA256 = SHA256()
    hasherSHA256.update(data: data)
    let finalHashSHA256 = hasherSHA256.finalize()
    
    var hasherSHA384 = SHA384()
    hasherSHA384.update(data: data)
    let finalHashSHA384 = hasherSHA384.finalize()
    
    var hasherSHA512 = SHA512()
    hasherSHA512.update(data: data)
    let finalHashSHA512 = hasherSHA512.finalize()
}

func testMACAlgorithms() throws {
    let key = SymmetricKey(size: .bits256)
    let data = "Data to authenticate".data(using: .utf8)!
    
    // HMAC with SHA-256
    let authCodeSHA256 = HMAC<SHA256>.authenticationCode(for: data, using: key)
    let isValidSHA256 = HMAC<SHA256>.isValidAuthenticationCode(authCodeSHA256, authenticating: data, using: key)
    
    // HMAC with SHA-384
    let authCodeSHA384 = HMAC<SHA384>.authenticationCode(for: data, using: key)
    let isValidSHA384 = HMAC<SHA384>.isValidAuthenticationCode(authCodeSHA384, authenticating: data, using: key)
    
    // HMAC with SHA-512
    let authCodeSHA512 = HMAC<SHA512>.authenticationCode(for: data, using: key)
    let isValidSHA512 = HMAC<SHA512>.isValidAuthenticationCode(authCodeSHA512, authenticating: data, using: key)
    
    // Incremental HMAC operations
    var hmacSHA256 = HMAC<SHA256>(key: key)
    hmacSHA256.update(data: data)
    let finalMACSHA256 = hmacSHA256.finalize()
    
    var hmacSHA384 = HMAC<SHA384>(key: key)
    hmacSHA384.update(data: data)
    let finalMACSHA384 = hmacSHA384.finalize()
    
    var hmacSHA512 = HMAC<SHA512>(key: key)
    hmacSHA512.update(data: data)
    let finalMACSHA512 = hmacSHA512.finalize()
}

func testKDFAlgorithms() throws {
    let inputKeyMaterial = SymmetricKey(size: .bits256)
    let salt = "salt".data(using: .utf8)!
    let info = "info".data(using: .utf8)!
    
    // HKDF with SHA-256
    let derivedKeySHA256 = HKDF<SHA256>.deriveKey(
        inputKeyMaterial: inputKeyMaterial,
        salt: salt,
        info: info,
        outputByteCount: 32
    )
    
    // HKDF with SHA-384
    let derivedKeySHA384 = HKDF<SHA384>.deriveKey(
        inputKeyMaterial: inputKeyMaterial,
        salt: salt,
        info: info,
        outputByteCount: 48
    )
    
    // HKDF with SHA-512
    let derivedKeySHA512 = HKDF<SHA512>.deriveKey(
        inputKeyMaterial: inputKeyMaterial,
        salt: salt,
        info: info,
        outputByteCount: 64
    )
    
    // HKDF expand operation
    let pseudoRandomKey = inputKeyMaterial
    let expandedKeySHA256 = HKDF<SHA256>.expand(
        pseudoRandomKey: pseudoRandomKey,
        info: info,
        outputByteCount: 32
    )
    
    let expandedKeySHA384 = HKDF<SHA384>.expand(
        pseudoRandomKey: pseudoRandomKey,
        info: info,
        outputByteCount: 48
    )
    
    let expandedKeySHA512 = HKDF<SHA512>.expand(
        pseudoRandomKey: pseudoRandomKey,
        info: info,
        outputByteCount: 64
    )
    
    // HKDF extract operation
    let extractedKeySHA256 = HKDF<SHA256>.extract(
        inputKeyMaterial: inputKeyMaterial,
        salt: salt
    )
    
    let extractedKeySHA384 = HKDF<SHA384>.extract(
        inputKeyMaterial: inputKeyMaterial,
        salt: salt
    )
    
    let extractedKeySHA512 = HKDF<SHA512>.extract(
        inputKeyMaterial: inputKeyMaterial,
        salt: salt
    )
}

// Main function to run all tests
func runAllTests() {
    do {
        try testSymmetricCiphers()
        try testAsymmetricAlgorithms()
        try testSignatureAlgorithms()
        testHashAlgorithms()
        try testMACAlgorithms()
        try testKDFAlgorithms()
        print("All CryptoKit tests completed successfully")
    } catch {
        print("Error running tests: \(error)")
    }
}

// Execute tests
runAllTests()
