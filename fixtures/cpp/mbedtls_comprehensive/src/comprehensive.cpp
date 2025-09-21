#include <mbedtls/aes.h>
#include <mbedtls/des.h>
#include <mbedtls/blowfish.h>
#include <mbedtls/camellia.h>
#include <mbedtls/aria.h>
#include <mbedtls/chacha20.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ccm.h>
#include <mbedtls/cipher.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/dhm.h>
#include <mbedtls/md.h>
#include <mbedtls/md2.h>
#include <mbedtls/md4.h>
#include <mbedtls/md5.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/ripemd160.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <mbedtls/bignum.h>
#include <cstring>
#include <cstdio>

void test_symmetric_ciphers() {
    unsigned char key[32] = {0};
    unsigned char key128[16] = {0};
    unsigned char key192[24] = {0};
    unsigned char key256[32] = {0};
    unsigned char iv[16] = {0};
    unsigned char plaintext[64] = "Test data for encryption";
    unsigned char ciphertext[128] = {0};
    unsigned char tag[16] = {0};
    size_t len = strlen((char*)plaintext);
    
    // AES-CBC
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_enc(&aes_ctx, key128, 128);
    mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, len, iv, plaintext, ciphertext);
    
    // AES-256-CBC
    mbedtls_aes_setkey_enc(&aes_ctx, key256, 256);
    mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, len, iv, plaintext, ciphertext);
    
    // AES-CTR
    size_t nc_off = 0;
    unsigned char nonce_counter[16] = {0};
    unsigned char stream_block[16] = {0};
    mbedtls_aes_crypt_ctr(&aes_ctx, len, &nc_off, nonce_counter, stream_block, plaintext, ciphertext);
    
    // AES-ECB
    mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT, plaintext, ciphertext);
    mbedtls_aes_free(&aes_ctx);
    
    // AES-GCM
    mbedtls_gcm_context gcm_ctx;
    mbedtls_gcm_init(&gcm_ctx);
    mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, key128, 128);
    mbedtls_gcm_crypt_and_tag(&gcm_ctx, MBEDTLS_GCM_ENCRYPT, len, iv, 12, NULL, 0, 
                               plaintext, ciphertext, 16, tag);
    
    // AES-256-GCM
    mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, key256, 256);
    mbedtls_gcm_crypt_and_tag(&gcm_ctx, MBEDTLS_GCM_ENCRYPT, len, iv, 12, NULL, 0,
                               plaintext, ciphertext, 16, tag);
    mbedtls_gcm_free(&gcm_ctx);
    
    // AES-CCM
    mbedtls_ccm_context ccm_ctx;
    mbedtls_ccm_init(&ccm_ctx);
    mbedtls_ccm_setkey(&ccm_ctx, MBEDTLS_CIPHER_ID_AES, key128, 128);
    mbedtls_ccm_encrypt_and_tag(&ccm_ctx, len, iv, 12, NULL, 0,
                                 plaintext, ciphertext, tag, 16);
    mbedtls_ccm_free(&ccm_ctx);
    
    // AES-OFB using cipher module
    mbedtls_cipher_context_t cipher_ctx;
    mbedtls_cipher_init(&cipher_ctx);
    const mbedtls_cipher_info_t *cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_OFB);
    mbedtls_cipher_setup(&cipher_ctx, cipher_info);
    mbedtls_cipher_setkey(&cipher_ctx, key128, 128, MBEDTLS_ENCRYPT);
    size_t olen;
    mbedtls_cipher_crypt(&cipher_ctx, iv, 16, plaintext, len, ciphertext, &olen);
    mbedtls_cipher_free(&cipher_ctx);
    
    // AES-CFB
    mbedtls_cipher_init(&cipher_ctx);
    cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CFB128);
    mbedtls_cipher_setup(&cipher_ctx, cipher_info);
    mbedtls_cipher_setkey(&cipher_ctx, key128, 128, MBEDTLS_ENCRYPT);
    mbedtls_cipher_crypt(&cipher_ctx, iv, 16, plaintext, len, ciphertext, &olen);
    mbedtls_cipher_free(&cipher_ctx);
    
    // DES
    mbedtls_des_context des_ctx;
    unsigned char des_key[8] = {0};
    mbedtls_des_init(&des_ctx);
    mbedtls_des_setkey_enc(&des_ctx, des_key);
    mbedtls_des_crypt_cbc(&des_ctx, MBEDTLS_DES_ENCRYPT, len, iv, plaintext, ciphertext);
    mbedtls_des_free(&des_ctx);
    
    // 3DES (Triple DES)
    mbedtls_des3_context des3_ctx;
    unsigned char des3_key[24] = {0};
    mbedtls_des3_init(&des3_ctx);
    mbedtls_des3_set3key_enc(&des3_ctx, des3_key);
    mbedtls_des3_crypt_cbc(&des3_ctx, MBEDTLS_DES_ENCRYPT, len, iv, plaintext, ciphertext);
    mbedtls_des3_free(&des3_ctx);
    
    // Blowfish
    mbedtls_blowfish_context bf_ctx;
    mbedtls_blowfish_init(&bf_ctx);
    mbedtls_blowfish_setkey(&bf_ctx, key128, 128);
    mbedtls_blowfish_crypt_cbc(&bf_ctx, MBEDTLS_BLOWFISH_ENCRYPT, len, iv, plaintext, ciphertext);
    mbedtls_blowfish_free(&bf_ctx);
    
    // Camellia
    mbedtls_camellia_context camellia_ctx;
    mbedtls_camellia_init(&camellia_ctx);
    mbedtls_camellia_setkey_enc(&camellia_ctx, key128, 128);
    mbedtls_camellia_crypt_cbc(&camellia_ctx, MBEDTLS_CAMELLIA_ENCRYPT, len, iv, plaintext, ciphertext);
    
    // Camellia-256
    mbedtls_camellia_setkey_enc(&camellia_ctx, key256, 256);
    mbedtls_camellia_crypt_cbc(&camellia_ctx, MBEDTLS_CAMELLIA_ENCRYPT, len, iv, plaintext, ciphertext);
    mbedtls_camellia_free(&camellia_ctx);
    
    // ARIA
    mbedtls_aria_context aria_ctx;
    mbedtls_aria_init(&aria_ctx);
    mbedtls_aria_setkey_enc(&aria_ctx, key128, 128);
    mbedtls_aria_crypt_cbc(&aria_ctx, MBEDTLS_ARIA_ENCRYPT, len, iv, plaintext, ciphertext);
    
    // ARIA-256
    mbedtls_aria_setkey_enc(&aria_ctx, key256, 256);
    mbedtls_aria_crypt_cbc(&aria_ctx, MBEDTLS_ARIA_ENCRYPT, len, iv, plaintext, ciphertext);
    mbedtls_aria_free(&aria_ctx);
    
    // ChaCha20
    mbedtls_chacha20_context chacha20_ctx;
    unsigned char nonce[12] = {0};
    mbedtls_chacha20_init(&chacha20_ctx);
    mbedtls_chacha20_setkey(&chacha20_ctx, key256);
    mbedtls_chacha20_crypt(key256, nonce, 0, len, plaintext, ciphertext);
    mbedtls_chacha20_free(&chacha20_ctx);
    
    // ChaCha20-Poly1305
    mbedtls_chachapoly_context chachapoly_ctx;
    mbedtls_chachapoly_init(&chachapoly_ctx);
    mbedtls_chachapoly_setkey(&chachapoly_ctx, key256);
    mbedtls_chachapoly_encrypt_and_tag(&chachapoly_ctx, len, nonce, NULL, 0,
                                        plaintext, ciphertext, tag);
    mbedtls_chachapoly_free(&chachapoly_ctx);
}

void test_asymmetric_crypto() {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "mbedtls_test";
    unsigned char hash[32] = {0};
    unsigned char sig[512] = {0};
    size_t sig_len = sizeof(sig);
    
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                          (const unsigned char *)pers, strlen(pers));
    
    // RSA
    mbedtls_rsa_context rsa_ctx;
    mbedtls_rsa_init(&rsa_ctx, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_rsa_gen_key(&rsa_ctx, mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537);
    
    // RSA PKCS#1 v1.5
    unsigned char plaintext[] = "Test message";
    unsigned char ciphertext[256];
    mbedtls_rsa_pkcs1_encrypt(&rsa_ctx, mbedtls_ctr_drbg_random, &ctr_drbg,
                               MBEDTLS_RSA_PUBLIC, sizeof(plaintext), plaintext, ciphertext);
    
    // RSA OAEP
    mbedtls_rsa_set_padding(&rsa_ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    mbedtls_rsa_rsaes_oaep_encrypt(&rsa_ctx, mbedtls_ctr_drbg_random, &ctr_drbg,
                                    MBEDTLS_RSA_PUBLIC, NULL, 0,
                                    sizeof(plaintext), plaintext, ciphertext);
    
    // RSA PSS
    mbedtls_rsa_pkcs1_sign(&rsa_ctx, mbedtls_ctr_drbg_random, &ctr_drbg,
                            MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256,
                            32, hash, sig);
    
    mbedtls_rsa_rsassa_pss_sign(&rsa_ctx, mbedtls_ctr_drbg_random, &ctr_drbg,
                                 MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256,
                                 32, hash, sig);
    
    // RSA 4096-bit
    mbedtls_rsa_context rsa4096_ctx;
    mbedtls_rsa_init(&rsa4096_ctx, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_rsa_gen_key(&rsa4096_ctx, mbedtls_ctr_drbg_random, &ctr_drbg, 4096, 65537);
    mbedtls_rsa_free(&rsa4096_ctx);
    
    mbedtls_rsa_free(&rsa_ctx);
    
    // ECC - ECDSA and ECDH
    mbedtls_ecdsa_context ecdsa_ctx;
    mbedtls_ecdsa_init(&ecdsa_ctx);
    
    // P-192
    mbedtls_ecdsa_genkey(&ecdsa_ctx, MBEDTLS_ECP_DP_SECP192R1, 
                          mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecdsa_write_signature(&ecdsa_ctx, MBEDTLS_MD_SHA256,
                                   hash, sizeof(hash), sig, &sig_len,
                                   mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecdsa_free(&ecdsa_ctx);
    
    // P-224
    mbedtls_ecdsa_init(&ecdsa_ctx);
    mbedtls_ecdsa_genkey(&ecdsa_ctx, MBEDTLS_ECP_DP_SECP224R1,
                          mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecdsa_free(&ecdsa_ctx);
    
    // P-256
    mbedtls_ecdsa_init(&ecdsa_ctx);
    mbedtls_ecdsa_genkey(&ecdsa_ctx, MBEDTLS_ECP_DP_SECP256R1,
                          mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecdsa_write_signature(&ecdsa_ctx, MBEDTLS_MD_SHA256,
                                   hash, sizeof(hash), sig, &sig_len,
                                   mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecdsa_free(&ecdsa_ctx);
    
    // P-384
    mbedtls_ecdsa_init(&ecdsa_ctx);
    mbedtls_ecdsa_genkey(&ecdsa_ctx, MBEDTLS_ECP_DP_SECP384R1,
                          mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecdsa_free(&ecdsa_ctx);
    
    // P-521
    mbedtls_ecdsa_init(&ecdsa_ctx);
    mbedtls_ecdsa_genkey(&ecdsa_ctx, MBEDTLS_ECP_DP_SECP521R1,
                          mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecdsa_free(&ecdsa_ctx);
    
    // secp256k1
    mbedtls_ecdsa_init(&ecdsa_ctx);
    mbedtls_ecdsa_genkey(&ecdsa_ctx, MBEDTLS_ECP_DP_SECP256K1,
                          mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecdsa_free(&ecdsa_ctx);
    
    // ECDH
    mbedtls_ecdh_context ecdh_ctx;
    mbedtls_ecdh_init(&ecdh_ctx);
    mbedtls_ecp_group_load(&ecdh_ctx.grp, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_ecdh_gen_public(&ecdh_ctx.grp, &ecdh_ctx.d, &ecdh_ctx.Q,
                             mbedtls_ctr_drbg_random, &ctr_drbg);
    
    unsigned char shared_secret[32];
    size_t shared_len;
    mbedtls_ecdh_calc_secret(&ecdh_ctx, &shared_len, shared_secret, sizeof(shared_secret),
                              mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecdh_free(&ecdh_ctx);
    
    // Curve25519
    mbedtls_ecdh_init(&ecdh_ctx);
    mbedtls_ecp_group_load(&ecdh_ctx.grp, MBEDTLS_ECP_DP_CURVE25519);
    mbedtls_ecdh_gen_public(&ecdh_ctx.grp, &ecdh_ctx.d, &ecdh_ctx.Q,
                             mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecdh_free(&ecdh_ctx);
    
    // Curve448
    mbedtls_ecdh_init(&ecdh_ctx);
    mbedtls_ecp_group_load(&ecdh_ctx.grp, MBEDTLS_ECP_DP_CURVE448);
    mbedtls_ecdh_gen_public(&ecdh_ctx.grp, &ecdh_ctx.d, &ecdh_ctx.Q,
                             mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecdh_free(&ecdh_ctx);
    
    // Diffie-Hellman
    mbedtls_dhm_context dhm_ctx;
    mbedtls_dhm_init(&dhm_ctx);
    mbedtls_mpi P, G;
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&G);
    
    // Set up DH parameters (simplified - normally would use proper values)
    mbedtls_mpi_read_string(&P, 16, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                                      "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                                      "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245");
    mbedtls_mpi_read_string(&G, 10, "2");
    mbedtls_dhm_set_group(&dhm_ctx, &P, &G);
    
    unsigned char dhm_buf[256];
    size_t dhm_len;
    mbedtls_dhm_make_public(&dhm_ctx, 256, dhm_buf, sizeof(dhm_buf),
                             mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_dhm_calc_secret(&dhm_ctx, dhm_buf, sizeof(dhm_buf), &dhm_len,
                             mbedtls_ctr_drbg_random, &ctr_drbg);
    
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&G);
    mbedtls_dhm_free(&dhm_ctx);
    
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void test_hash_functions() {
    unsigned char data[] = "Test data for hashing";
    unsigned char output[64];
    
    // MD2
    mbedtls_md2_context md2_ctx;
    mbedtls_md2_init(&md2_ctx);
    mbedtls_md2_starts_ret(&md2_ctx);
    mbedtls_md2_update_ret(&md2_ctx, data, sizeof(data));
    mbedtls_md2_finish_ret(&md2_ctx, output);
    mbedtls_md2_free(&md2_ctx);
    
    // Alternative MD2
    mbedtls_md2_ret(data, sizeof(data), output);
    
    // MD4
    mbedtls_md4_context md4_ctx;
    mbedtls_md4_init(&md4_ctx);
    mbedtls_md4_starts_ret(&md4_ctx);
    mbedtls_md4_update_ret(&md4_ctx, data, sizeof(data));
    mbedtls_md4_finish_ret(&md4_ctx, output);
    mbedtls_md4_free(&md4_ctx);
    
    // Alternative MD4
    mbedtls_md4_ret(data, sizeof(data), output);
    
    // MD5
    mbedtls_md5_context md5_ctx;
    mbedtls_md5_init(&md5_ctx);
    mbedtls_md5_starts_ret(&md5_ctx);
    mbedtls_md5_update_ret(&md5_ctx, data, sizeof(data));
    mbedtls_md5_finish_ret(&md5_ctx, output);
    mbedtls_md5_free(&md5_ctx);
    
    // Alternative MD5
    mbedtls_md5_ret(data, sizeof(data), output);
    
    // SHA-1
    mbedtls_sha1_context sha1_ctx;
    mbedtls_sha1_init(&sha1_ctx);
    mbedtls_sha1_starts_ret(&sha1_ctx);
    mbedtls_sha1_update_ret(&sha1_ctx, data, sizeof(data));
    mbedtls_sha1_finish_ret(&sha1_ctx, output);
    mbedtls_sha1_free(&sha1_ctx);
    
    // Alternative SHA-1
    mbedtls_sha1_ret(data, sizeof(data), output);
    
    // SHA-224
    mbedtls_sha256_context sha224_ctx;
    mbedtls_sha256_init(&sha224_ctx);
    mbedtls_sha256_starts_ret(&sha224_ctx, 1); // 1 for SHA-224
    mbedtls_sha256_update_ret(&sha224_ctx, data, sizeof(data));
    mbedtls_sha256_finish_ret(&sha224_ctx, output);
    mbedtls_sha256_free(&sha224_ctx);
    
    // Alternative SHA-224
    mbedtls_sha256_ret(data, sizeof(data), output, 1);
    
    // SHA-256
    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts_ret(&sha256_ctx, 0); // 0 for SHA-256
    mbedtls_sha256_update_ret(&sha256_ctx, data, sizeof(data));
    mbedtls_sha256_finish_ret(&sha256_ctx, output);
    mbedtls_sha256_free(&sha256_ctx);
    
    // Alternative SHA-256
    mbedtls_sha256_ret(data, sizeof(data), output, 0);
    
    // SHA-384
    mbedtls_sha512_context sha384_ctx;
    mbedtls_sha512_init(&sha384_ctx);
    mbedtls_sha512_starts_ret(&sha384_ctx, 1); // 1 for SHA-384
    mbedtls_sha512_update_ret(&sha384_ctx, data, sizeof(data));
    mbedtls_sha512_finish_ret(&sha384_ctx, output);
    mbedtls_sha512_free(&sha384_ctx);
    
    // Alternative SHA-384
    mbedtls_sha512_ret(data, sizeof(data), output, 1);
    
    // SHA-512
    mbedtls_sha512_context sha512_ctx;
    mbedtls_sha512_init(&sha512_ctx);
    mbedtls_sha512_starts_ret(&sha512_ctx, 0); // 0 for SHA-512
    mbedtls_sha512_update_ret(&sha512_ctx, data, sizeof(data));
    mbedtls_sha512_finish_ret(&sha512_ctx, output);
    mbedtls_sha512_free(&sha512_ctx);
    
    // Alternative SHA-512
    mbedtls_sha512_ret(data, sizeof(data), output, 0);
    
    // RIPEMD-160
    mbedtls_ripemd160_context ripemd_ctx;
    mbedtls_ripemd160_init(&ripemd_ctx);
    mbedtls_ripemd160_starts_ret(&ripemd_ctx);
    mbedtls_ripemd160_update_ret(&ripemd_ctx, data, sizeof(data));
    mbedtls_ripemd160_finish_ret(&ripemd_ctx, output);
    mbedtls_ripemd160_free(&ripemd_ctx);
    
    // Alternative RIPEMD-160
    mbedtls_ripemd160_ret(data, sizeof(data), output);
    
    // Using generic MD interface
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t md_ctx;
    
    // Generic SHA-256
    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 0);
    mbedtls_md_starts(&md_ctx);
    mbedtls_md_update(&md_ctx, data, sizeof(data));
    mbedtls_md_finish(&md_ctx, output);
    mbedtls_md_free(&md_ctx);
}

void test_kdf_functions() {
    unsigned char password[] = "password";
    unsigned char salt[] = "salt1234";
    unsigned char output[32];
    
    // PBKDF2 with HMAC-SHA1
    mbedtls_pkcs5_pbkdf2_hmac_sha1(password, sizeof(password),
                                    salt, sizeof(salt),
                                    10000, sizeof(output), output);
    
    // PBKDF2 with generic MD (SHA-256)
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 1); // 1 for HMAC
    mbedtls_pkcs5_pbkdf2_hmac(&md_ctx, password, sizeof(password),
                               salt, sizeof(salt),
                               10000, sizeof(output), output);
    mbedtls_md_free(&md_ctx);
    
    // HKDF with SHA-256
    unsigned char ikm[32] = {0}; // Input key material
    unsigned char info[] = "info";
    unsigned char okm[42]; // Output key material
    
    mbedtls_hkdf(md_info, salt, sizeof(salt),
                  ikm, sizeof(ikm),
                  info, sizeof(info),
                  okm, sizeof(okm));
    
    // HKDF Extract
    unsigned char prk[32]; // Pseudorandom key
    mbedtls_hkdf_extract(md_info, salt, sizeof(salt),
                          ikm, sizeof(ikm), prk);
    
    // HKDF Expand
    mbedtls_hkdf_expand(md_info, prk, sizeof(prk),
                         info, sizeof(info),
                         okm, sizeof(okm));
}

void test_mac_functions() {
    unsigned char key[] = "secret_key";
    unsigned char data[] = "data to authenticate";
    unsigned char output[64];
    
    // HMAC using MD interface
    const mbedtls_md_info_t *md_info;
    
    // HMAC-SHA256
    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_hmac(md_info, key, sizeof(key), data, sizeof(data), output);
    
    // HMAC-SHA512
    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    mbedtls_md_hmac(md_info, key, sizeof(key), data, sizeof(data), output);
    
    // HMAC with context
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 1); // 1 for HMAC
    mbedtls_md_hmac_starts(&md_ctx, key, sizeof(key));
    mbedtls_md_hmac_update(&md_ctx, data, sizeof(data));
    mbedtls_md_hmac_finish(&md_ctx, output);
    mbedtls_md_free(&md_ctx);
}

int main() {
    printf("Testing mbedTLS comprehensive cryptographic algorithms...\n");
    
    test_symmetric_ciphers();
    test_asymmetric_crypto();
    test_hash_functions();
    test_kdf_functions();
    test_mac_functions();
    
    printf("All mbedTLS tests completed.\n");
    return 0;
}
