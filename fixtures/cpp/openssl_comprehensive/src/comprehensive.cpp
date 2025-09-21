#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/blowfish.h>
#include <openssl/rc4.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <cstring>
#include <memory>
#include <vector>

void test_symmetric_ciphers() {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[32], iv[16];
    
    // AES-128-CBC
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv);
    
    // AES-256-CBC  
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    
    // AES-128-GCM
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
    
    // AES-256-GCM
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
    
    // DES-EDE3-CBC (3DES)
    EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), nullptr, key, iv);
    
    // DES-CBC
    EVP_EncryptInit_ex(ctx, EVP_des_cbc(), nullptr, key, iv);
    
    // ChaCha20
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr, key, iv);
    
    // ChaCha20-Poly1305
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv);
    
    // Blowfish-CBC
    EVP_EncryptInit_ex(ctx, EVP_bf_cbc(), nullptr, key, iv);
    
    // RC4
    EVP_EncryptInit_ex(ctx, EVP_rc4(), nullptr, key, nullptr);
    
    EVP_CIPHER_CTX_free(ctx);
}

void test_asymmetric_algorithms() {
    EVP_PKEY_CTX *pctx;
    EVP_PKEY *pkey = nullptr;
    
    // RSA 1024-bit
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 1024);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    
    // RSA 2048-bit
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    
    // RSA 4096-bit
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 4096);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    
    // ECDSA P-256
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    
    // ECDSA P-384
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    
    // ECDSA P-521
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp521r1);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    
    // Diffie-Hellman (DH)
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr);
    EVP_PKEY_paramgen_init(pctx);
    EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, 2048);
    EVP_PKEY_CTX_set_dh_paramgen_generator(pctx, 2);
    EVP_PKEY *params = nullptr;
    EVP_PKEY_paramgen(pctx, &params);
    EVP_PKEY_CTX_free(pctx);
    
    // Generate DH key pair
    pctx = EVP_PKEY_CTX_new(params, nullptr);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(params);
    EVP_PKEY_free(pkey);
    
    // DSA
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, nullptr);
    EVP_PKEY_paramgen_init(pctx);
    EVP_PKEY_CTX_set_dsa_paramgen_bits(pctx, 2048);
    EVP_PKEY_paramgen(pctx, &params);
    EVP_PKEY_CTX_free(pctx);
    
    pctx = EVP_PKEY_CTX_new(params, nullptr);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(params);
    EVP_PKEY_free(pkey);
}

void test_hash_algorithms() {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    const char *data = "test data";
    
    // SHA-1
    EVP_DigestInit_ex(mdctx, EVP_sha1(), nullptr);
    EVP_DigestUpdate(mdctx, data, strlen(data));
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    
    // SHA-224
    EVP_DigestInit_ex(mdctx, EVP_sha224(), nullptr);
    EVP_DigestUpdate(mdctx, data, strlen(data));
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    
    // SHA-256
    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, data, strlen(data));
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    
    // SHA-384
    EVP_DigestInit_ex(mdctx, EVP_sha384(), nullptr);
    EVP_DigestUpdate(mdctx, data, strlen(data));
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    
    // SHA-512
    EVP_DigestInit_ex(mdctx, EVP_sha512(), nullptr);
    EVP_DigestUpdate(mdctx, data, strlen(data));
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    
    // SHA3-224
    EVP_DigestInit_ex(mdctx, EVP_sha3_224(), nullptr);
    EVP_DigestUpdate(mdctx, data, strlen(data));
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    
    // SHA3-256
    EVP_DigestInit_ex(mdctx, EVP_sha3_256(), nullptr);
    EVP_DigestUpdate(mdctx, data, strlen(data));
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    
    // SHA3-384
    EVP_DigestInit_ex(mdctx, EVP_sha3_384(), nullptr);
    EVP_DigestUpdate(mdctx, data, strlen(data));
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    
    // SHA3-512
    EVP_DigestInit_ex(mdctx, EVP_sha3_512(), nullptr);
    EVP_DigestUpdate(mdctx, data, strlen(data));
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    
    // BLAKE2b
    EVP_DigestInit_ex(mdctx, EVP_blake2b512(), nullptr);
    EVP_DigestUpdate(mdctx, data, strlen(data));
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    
    // BLAKE2s
    EVP_DigestInit_ex(mdctx, EVP_blake2s256(), nullptr);
    EVP_DigestUpdate(mdctx, data, strlen(data));
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    
    // MD5
    EVP_DigestInit_ex(mdctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(mdctx, data, strlen(data));
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    
    EVP_MD_CTX_free(mdctx);
}

void test_kdf_algorithms() {
    unsigned char out[64];
    const char *pass = "password";
    const unsigned char salt[] = "salt";
    
    // PKCS5_PBKDF2_HMAC (with SHA256)
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, sizeof(salt)-1, 
                      10000, EVP_sha256(), 32, out);
    
    // PKCS5_PBKDF2_HMAC_SHA1
    PKCS5_PBKDF2_HMAC_SHA1(pass, strlen(pass), salt, sizeof(salt)-1,
                           10000, 32, out);
    
    // Scrypt
    EVP_PBE_scrypt(pass, strlen(pass), salt, sizeof(salt)-1,
                   16384, 8, 1, 0, out, 32);
    
    // HKDF using EVP_PKEY_derive
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, sizeof(salt)-1);
    EVP_PKEY_CTX_set1_hkdf_key(pctx, (unsigned char*)pass, strlen(pass));
    size_t outlen = 32;
    EVP_PKEY_derive(pctx, out, &outlen);
    EVP_PKEY_CTX_free(pctx);
}

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    test_symmetric_ciphers();
    test_asymmetric_algorithms();
    test_hash_algorithms();
    test_kdf_algorithms();
    
    // Cleanup
    EVP_cleanup();
    ERR_free_strings();
    
    return 0;
}
