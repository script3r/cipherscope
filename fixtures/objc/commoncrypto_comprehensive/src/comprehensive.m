#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

void testSymmetricCiphers() {
    // Test data
    uint8_t key128[kCCKeySizeAES128] = {0};
    uint8_t key192[kCCKeySizeAES192] = {0};
    uint8_t key256[kCCKeySizeAES256] = {0};
    uint8_t keyDES[kCCKeySizeDES] = {0};
    uint8_t key3DES[kCCKeySize3DES] = {0};
    uint8_t iv[kCCBlockSizeAES128] = {0};
    uint8_t plaintext[] = "Test data for encryption";
    size_t plaintextLen = strlen((char *)plaintext);
    uint8_t ciphertext[1024] = {0};
    size_t ciphertextLen = 0;
    
    // AES-128 ECB
    CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionECBMode,
            key128, kCCKeySizeAES128, NULL,
            plaintext, plaintextLen,
            ciphertext, sizeof(ciphertext), &ciphertextLen);
    
    // AES-128 CBC
    CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
            key128, kCCKeySizeAES128, iv,
            plaintext, plaintextLen,
            ciphertext, sizeof(ciphertext), &ciphertextLen);
    
    // AES (same as AES-128)
    CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
            key128, kCCKeySizeAES128, iv,
            plaintext, plaintextLen,
            ciphertext, sizeof(ciphertext), &ciphertextLen);
    
    // AES-192
    CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
            key192, kCCKeySizeAES192, iv,
            plaintext, plaintextLen,
            ciphertext, sizeof(ciphertext), &ciphertextLen);
    
    // AES-256
    CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
            key256, kCCKeySizeAES256, iv,
            plaintext, plaintextLen,
            ciphertext, sizeof(ciphertext), &ciphertextLen);
    
    // DES
    uint8_t ivDES[kCCBlockSizeDES] = {0};
    CCCrypt(kCCEncrypt, kCCAlgorithmDES, kCCOptionPKCS7Padding,
            keyDES, kCCKeySizeDES, ivDES,
            plaintext, plaintextLen,
            ciphertext, sizeof(ciphertext), &ciphertextLen);
    
    // 3DES
    CCCrypt(kCCEncrypt, kCCAlgorithm3DES, kCCOptionPKCS7Padding,
            key3DES, kCCKeySize3DES, ivDES,
            plaintext, plaintextLen,
            ciphertext, sizeof(ciphertext), &ciphertextLen);
    
    // RC4
    uint8_t keyRC4[16] = {0};
    CCCrypt(kCCEncrypt, kCCAlgorithmRC4, 0,
            keyRC4, sizeof(keyRC4), NULL,
            plaintext, plaintextLen,
            ciphertext, sizeof(ciphertext), &ciphertextLen);
    
    // RC2
    uint8_t keyRC2[16] = {0};
    uint8_t ivRC2[kCCBlockSizeRC2] = {0};
    CCCrypt(kCCEncrypt, kCCAlgorithmRC2, kCCOptionPKCS7Padding,
            keyRC2, sizeof(keyRC2), ivRC2,
            plaintext, plaintextLen,
            ciphertext, sizeof(ciphertext), &ciphertextLen);
    
    // Blowfish
    uint8_t keyBlowfish[16] = {0};
    uint8_t ivBlowfish[kCCBlockSizeBlowfish] = {0};
    CCCrypt(kCCEncrypt, kCCAlgorithmBlowfish, kCCOptionPKCS7Padding,
            keyBlowfish, sizeof(keyBlowfish), ivBlowfish,
            plaintext, plaintextLen,
            ciphertext, sizeof(ciphertext), &ciphertextLen);
    
    // CAST
    uint8_t keyCAST[16] = {0};
    uint8_t ivCAST[kCCBlockSizeCAST] = {0};
    CCCrypt(kCCEncrypt, kCCAlgorithmCAST, kCCOptionPKCS7Padding,
            keyCAST, sizeof(keyCAST), ivCAST,
            plaintext, plaintextLen,
            ciphertext, sizeof(ciphertext), &ciphertextLen);
}

void testCipherModes() {
    uint8_t key[kCCKeySizeAES128] = {0};
    uint8_t iv[kCCBlockSizeAES128] = {0};
    uint8_t plaintext[] = "Test data for modes";
    size_t plaintextLen = strlen((char *)plaintext);
    uint8_t ciphertext[1024] = {0};
    size_t ciphertextLen = 0;
    
    // ECB mode
    CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionECBMode,
            key, kCCKeySizeAES128, NULL,
            plaintext, plaintextLen,
            ciphertext, sizeof(ciphertext), &ciphertextLen);
    
    // CBC mode (default)
    CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
            key, kCCKeySizeAES128, iv,
            plaintext, plaintextLen,
            ciphertext, sizeof(ciphertext), &ciphertextLen);
    
    // Using CCCryptorCreate for more control
    CCCryptorRef cryptor = NULL;
    
    // CFB mode
    CCCryptorCreateWithMode(kCCEncrypt, kCCModeCFB, kCCAlgorithmAES128,
                            kCCOptionPKCS7Padding, iv, key, kCCKeySizeAES128,
                            NULL, 0, 0, 0, &cryptor);
    CCCryptorUpdate(cryptor, plaintext, plaintextLen, ciphertext, sizeof(ciphertext), &ciphertextLen);
    CCCryptorFinal(cryptor, ciphertext + ciphertextLen, sizeof(ciphertext) - ciphertextLen, &ciphertextLen);
    CCCryptorRelease(cryptor);
    
    // CTR mode
    CCCryptorCreateWithMode(kCCEncrypt, kCCModeCTR, kCCAlgorithmAES128,
                            kCCOptionPKCS7Padding, iv, key, kCCKeySizeAES128,
                            NULL, 0, 0, kCCModeOptionCTR_BE, &cryptor);
    CCCryptorUpdate(cryptor, plaintext, plaintextLen, ciphertext, sizeof(ciphertext), &ciphertextLen);
    CCCryptorFinal(cryptor, ciphertext + ciphertextLen, sizeof(ciphertext) - ciphertextLen, &ciphertextLen);
    CCCryptorRelease(cryptor);
    
    // OFB mode
    CCCryptorCreateWithMode(kCCEncrypt, kCCModeOFB, kCCAlgorithmAES128,
                            kCCOptionPKCS7Padding, iv, key, kCCKeySizeAES128,
                            NULL, 0, 0, 0, &cryptor);
    CCCryptorUpdate(cryptor, plaintext, plaintextLen, ciphertext, sizeof(ciphertext), &ciphertextLen);
    CCCryptorFinal(cryptor, ciphertext + ciphertextLen, sizeof(ciphertext) - ciphertextLen, &ciphertextLen);
    CCCryptorRelease(cryptor);
    
    // RC4 mode
    CCCryptorCreateWithMode(kCCEncrypt, kCCModeRC4, kCCAlgorithmRC4,
                            0, NULL, key, 16,
                            NULL, 0, 0, 0, &cryptor);
    CCCryptorUpdate(cryptor, plaintext, plaintextLen, ciphertext, sizeof(ciphertext), &ciphertextLen);
    CCCryptorFinal(cryptor, ciphertext + ciphertextLen, sizeof(ciphertext) - ciphertextLen, &ciphertextLen);
    CCCryptorRelease(cryptor);
    
    // GCM mode (requires more setup)
    uint8_t tag[16] = {0};
    size_t tagLength = sizeof(tag);
    uint8_t aad[] = "Additional authenticated data";
    size_t aadLen = strlen((char *)aad);
    
    CCCryptorGCMOneshotEncrypt(kCCAlgorithmAES, key, kCCKeySizeAES128,
                               iv, sizeof(iv),
                               aad, aadLen,
                               plaintext, plaintextLen,
                               ciphertext, tag, &tagLength);
    
    // Alternative GCM setup
    CCCryptorCreateWithMode(kCCEncrypt, kCCModeGCM, kCCAlgorithmAES128,
                            kCCOptionPKCS7Padding, iv, key, kCCKeySizeAES128,
                            NULL, 0, 0, 0, &cryptor);
    CCCryptorGCMAddAAD(cryptor, aad, aadLen);
    CCCryptorUpdate(cryptor, plaintext, plaintextLen, ciphertext, sizeof(ciphertext), &ciphertextLen);
    CCCryptorFinal(cryptor, ciphertext + ciphertextLen, sizeof(ciphertext) - ciphertextLen, &ciphertextLen);
    CCCryptorGCMFinalize(cryptor, tag, &tagLength);
    CCCryptorRelease(cryptor);
}

void testHashAlgorithms() {
    uint8_t data[] = "Data to hash";
    size_t dataLen = strlen((char *)data);
    uint8_t hash[CC_SHA512_DIGEST_LENGTH] = {0};
    
    // MD2
    CC_MD2(data, (CC_LONG)dataLen, hash);
    
    // MD2 with context
    CC_MD2_CTX md2ctx;
    CC_MD2_Init(&md2ctx);
    CC_MD2_Update(&md2ctx, data, (CC_LONG)dataLen);
    CC_MD2_Final(hash, &md2ctx);
    
    // MD4
    CC_MD4(data, (CC_LONG)dataLen, hash);
    
    // MD4 with context
    CC_MD4_CTX md4ctx;
    CC_MD4_Init(&md4ctx);
    CC_MD4_Update(&md4ctx, data, (CC_LONG)dataLen);
    CC_MD4_Final(hash, &md4ctx);
    
    // MD5
    CC_MD5(data, (CC_LONG)dataLen, hash);
    
    // MD5 with context
    CC_MD5_CTX md5ctx;
    CC_MD5_Init(&md5ctx);
    CC_MD5_Update(&md5ctx, data, (CC_LONG)dataLen);
    CC_MD5_Final(hash, &md5ctx);
    
    // SHA-1
    CC_SHA1(data, (CC_LONG)dataLen, hash);
    
    // SHA-1 with context
    CC_SHA1_CTX sha1ctx;
    CC_SHA1_Init(&sha1ctx);
    CC_SHA1_Update(&sha1ctx, data, (CC_LONG)dataLen);
    CC_SHA1_Final(hash, &sha1ctx);
    
    // SHA-224
    CC_SHA224(data, (CC_LONG)dataLen, hash);
    
    // SHA-224 with context
    CC_SHA256_CTX sha224ctx;  // SHA-224 uses SHA256_CTX
    CC_SHA224_Init(&sha224ctx);
    CC_SHA224_Update(&sha224ctx, data, (CC_LONG)dataLen);
    CC_SHA224_Final(hash, &sha224ctx);
    
    // SHA-256
    CC_SHA256(data, (CC_LONG)dataLen, hash);
    
    // SHA-256 with context
    CC_SHA256_CTX sha256ctx;
    CC_SHA256_Init(&sha256ctx);
    CC_SHA256_Update(&sha256ctx, data, (CC_LONG)dataLen);
    CC_SHA256_Final(hash, &sha256ctx);
    
    // SHA-384
    CC_SHA384(data, (CC_LONG)dataLen, hash);
    
    // SHA-384 with context
    CC_SHA512_CTX sha384ctx;  // SHA-384 uses SHA512_CTX
    CC_SHA384_Init(&sha384ctx);
    CC_SHA384_Update(&sha384ctx, data, (CC_LONG)dataLen);
    CC_SHA384_Final(hash, &sha384ctx);
    
    // SHA-512
    CC_SHA512(data, (CC_LONG)dataLen, hash);
    
    // SHA-512 with context
    CC_SHA512_CTX sha512ctx;
    CC_SHA512_Init(&sha512ctx);
    CC_SHA512_Update(&sha512ctx, data, (CC_LONG)dataLen);
    CC_SHA512_Final(hash, &sha512ctx);
}

void testHMACAlgorithms() {
    uint8_t key[] = "HMAC key";
    size_t keyLen = strlen((char *)key);
    uint8_t data[] = "Data to authenticate";
    size_t dataLen = strlen((char *)data);
    uint8_t mac[CC_SHA512_DIGEST_LENGTH] = {0};
    
    // HMAC-MD5
    CCHmac(kCCHmacAlgMD5, key, keyLen, data, dataLen, mac);
    
    // HMAC-MD5 with context
    CCHmacContext hmacMD5ctx;
    CCHmacInit(&hmacMD5ctx, kCCHmacAlgMD5, key, keyLen);
    CCHmacUpdate(&hmacMD5ctx, data, dataLen);
    CCHmacFinal(&hmacMD5ctx, mac);
    
    // HMAC-SHA1
    CCHmac(kCCHmacAlgSHA1, key, keyLen, data, dataLen, mac);
    
    // HMAC-SHA1 with context
    CCHmacContext hmacSHA1ctx;
    CCHmacInit(&hmacSHA1ctx, kCCHmacAlgSHA1, key, keyLen);
    CCHmacUpdate(&hmacSHA1ctx, data, dataLen);
    CCHmacFinal(&hmacSHA1ctx, mac);
    
    // HMAC-SHA224
    CCHmac(kCCHmacAlgSHA224, key, keyLen, data, dataLen, mac);
    
    // HMAC-SHA224 with context
    CCHmacContext hmacSHA224ctx;
    CCHmacInit(&hmacSHA224ctx, kCCHmacAlgSHA224, key, keyLen);
    CCHmacUpdate(&hmacSHA224ctx, data, dataLen);
    CCHmacFinal(&hmacSHA224ctx, mac);
    
    // HMAC-SHA256
    CCHmac(kCCHmacAlgSHA256, key, keyLen, data, dataLen, mac);
    
    // HMAC-SHA256 with context
    CCHmacContext hmacSHA256ctx;
    CCHmacInit(&hmacSHA256ctx, kCCHmacAlgSHA256, key, keyLen);
    CCHmacUpdate(&hmacSHA256ctx, data, dataLen);
    CCHmacFinal(&hmacSHA256ctx, mac);
    
    // HMAC-SHA384
    CCHmac(kCCHmacAlgSHA384, key, keyLen, data, dataLen, mac);
    
    // HMAC-SHA384 with context
    CCHmacContext hmacSHA384ctx;
    CCHmacInit(&hmacSHA384ctx, kCCHmacAlgSHA384, key, keyLen);
    CCHmacUpdate(&hmacSHA384ctx, data, dataLen);
    CCHmacFinal(&hmacSHA384ctx, mac);
    
    // HMAC-SHA512
    CCHmac(kCCHmacAlgSHA512, key, keyLen, data, dataLen, mac);
    
    // HMAC-SHA512 with context
    CCHmacContext hmacSHA512ctx;
    CCHmacInit(&hmacSHA512ctx, kCCHmacAlgSHA512, key, keyLen);
    CCHmacUpdate(&hmacSHA512ctx, data, dataLen);
    CCHmacFinal(&hmacSHA512ctx, mac);
}

void testKDFAlgorithms() {
    char *password = "password";
    uint8_t salt[] = "salt1234";
    size_t saltLen = strlen((char *)salt);
    uint8_t derivedKey[32] = {0};
    
    // PBKDF2 with HMAC-SHA1
    CCKeyDerivationPBKDF(kCCPBKDF2, password, strlen(password),
                         salt, saltLen,
                         kCCPRFHmacAlgSHA1, 10000,
                         derivedKey, sizeof(derivedKey));
    
    // PBKDF2 with HMAC-SHA224
    CCKeyDerivationPBKDF(kCCPBKDF2, password, strlen(password),
                         salt, saltLen,
                         kCCPRFHmacAlgSHA224, 10000,
                         derivedKey, sizeof(derivedKey));
    
    // PBKDF2 with HMAC-SHA256
    CCKeyDerivationPBKDF(kCCPBKDF2, password, strlen(password),
                         salt, saltLen,
                         kCCPRFHmacAlgSHA256, 10000,
                         derivedKey, sizeof(derivedKey));
    
    // PBKDF2 with HMAC-SHA384
    CCKeyDerivationPBKDF(kCCPBKDF2, password, strlen(password),
                         salt, saltLen,
                         kCCPRFHmacAlgSHA384, 10000,
                         derivedKey, sizeof(derivedKey));
    
    // PBKDF2 with HMAC-SHA512
    CCKeyDerivationPBKDF(kCCPBKDF2, password, strlen(password),
                         salt, saltLen,
                         kCCPRFHmacAlgSHA512, 10000,
                         derivedKey, sizeof(derivedKey));
    
    // Alternative PBKDF2 call
    CCPBKDFAlgorithm pbkdf2Alg = kCCPBKDF2;
    CCPseudoRandomAlgorithm prf = kCCPRFHmacAlgSHA256;
    uint rounds = 100000;
    
    CCKeyDerivationPBKDF(pbkdf2Alg, password, strlen(password),
                         salt, saltLen,
                         prf, rounds,
                         derivedKey, sizeof(derivedKey));
}

int main() {
    @autoreleasepool {
        NSLog(@"Testing CommonCrypto algorithms...");
        
        testSymmetricCiphers();
        testCipherModes();
        testHashAlgorithms();
        testHMACAlgorithms();
        testKDFAlgorithms();
        
        NSLog(@"All CommonCrypto tests completed");
    }
    return 0;
}
