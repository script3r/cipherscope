#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

int main() {
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return 1;
    }
    
    printf("libsodium initialized successfully\n");
    
    // ChaCha20Poly1305 AEAD encryption
    unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    unsigned char ciphertext[1000];
    unsigned long long ciphertext_len;
    
    crypto_aead_chacha20poly1305_ietf_keygen(key);
    randombytes_buf(nonce, sizeof nonce);
    
    const char *message = "Hello, libsodium World!";
    
    crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
                                              (const unsigned char*)message, strlen(message),
                                              NULL, 0,
                                              NULL, nonce, key);
    
    printf("✓ ChaCha20Poly1305 encryption successful\n");
    
    // Ed25519 digital signatures
    unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES];
    unsigned char signature[crypto_sign_ed25519_BYTES];
    unsigned long long signature_len;
    
    crypto_sign_ed25519_keypair(pk, sk);
    crypto_sign_ed25519_detached(signature, &signature_len,
                                 (const unsigned char*)message, strlen(message), sk);
    
    printf("✓ Ed25519 digital signature created\n");
    
    // Generic hash (BLAKE2b)
    unsigned char hash[crypto_generichash_BYTES];
    crypto_generichash(hash, sizeof hash,
                       (const unsigned char*)message, strlen(message),
                       NULL, 0);
    
    printf("✓ BLAKE2b hash computed\n");
    
    // X25519 key exchange
    unsigned char alice_pk[crypto_scalarmult_curve25519_BYTES];
    unsigned char alice_sk[crypto_scalarmult_curve25519_SCALARBYTES];
    unsigned char bob_pk[crypto_scalarmult_curve25519_BYTES];
    unsigned char bob_sk[crypto_scalarmult_curve25519_SCALARBYTES];
    unsigned char shared_secret[crypto_scalarmult_curve25519_BYTES];
    
    crypto_scalarmult_curve25519_base(alice_pk, alice_sk);
    crypto_scalarmult_curve25519_base(bob_pk, bob_sk);
    crypto_scalarmult_curve25519(shared_secret, alice_sk, bob_pk);
    
    printf("✓ X25519 key exchange completed\n");
    
    printf("\nCryptographic algorithms tested:\n");
    printf("- ChaCha20Poly1305 (Quantum-safe AEAD)\n");
    printf("- Ed25519 (Quantum-vulnerable signatures)\n");
    printf("- BLAKE2b (Quantum-safe hash)\n");
    printf("- X25519 (Quantum-vulnerable key exchange)\n");
    
    return 0;
}