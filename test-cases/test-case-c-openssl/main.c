#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <sodium.h>

int main() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    
    // Generate RSA key pair
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        return 1;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize key generation\n");
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        fprintf(stderr, "Failed to set key size\n");
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate key\n");
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    
    printf("RSA 2048-bit key pair generated successfully!\n");
    
    // Initialize libsodium
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    
    // Test ChaCha20Poly1305 with libsodium
    unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    
    crypto_aead_chacha20poly1305_ietf_keygen(key);
    randombytes_buf(nonce, sizeof nonce);
    
    const char *message = "Hello, World!";
    unsigned char ciphertext[strlen(message) + crypto_aead_chacha20poly1305_ietf_ABYTES];
    unsigned long long ciphertext_len;
    
    crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
                                              (const unsigned char*)message, strlen(message),
                                              NULL, 0,
                                              NULL, nonce, key);
    
    printf("ChaCha20Poly1305 encryption successful!\n");
    
    // Cleanup
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    EVP_cleanup();
    
    return 0;
}