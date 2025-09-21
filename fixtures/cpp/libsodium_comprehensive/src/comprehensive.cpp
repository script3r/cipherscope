#include <sodium.h>
#include <cstring>
#include <vector>
#include <iostream>

void test_secretbox() {
    // XSalsa20-Poly1305 (secretbox)
    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char plaintext[] = "Test message";
    unsigned char ciphertext[sizeof(plaintext) + crypto_secretbox_MACBYTES];
    
    crypto_secretbox_keygen(key);
    randombytes_buf(nonce, sizeof(nonce));
    
    // Encrypt with XSalsa20-Poly1305
    crypto_secretbox_easy(ciphertext, plaintext, sizeof(plaintext), nonce, key);
    
    // Decrypt
    unsigned char decrypted[sizeof(plaintext)];
    crypto_secretbox_open_easy(decrypted, ciphertext, sizeof(ciphertext), nonce, key);
    
    // Alternative API
    crypto_secretbox(ciphertext, plaintext, sizeof(plaintext), nonce, key);
    crypto_secretbox_open(decrypted, ciphertext, sizeof(ciphertext), nonce, key);
}

void test_aead_algorithms() {
    unsigned char key[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    unsigned char plaintext[] = "Test message";
    unsigned char ad[] = "Additional data";
    unsigned char ciphertext[sizeof(plaintext) + crypto_aead_chacha20poly1305_IETF_ABYTES];
    unsigned long long ciphertext_len;
    
    // ChaCha20-Poly1305-IETF
    crypto_aead_chacha20poly1305_ietf_keygen(key);
    randombytes_buf(nonce, sizeof(nonce));
    
    crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext, &ciphertext_len,
        plaintext, sizeof(plaintext),
        ad, sizeof(ad),
        NULL, nonce, key
    );
    
    unsigned char decrypted[sizeof(plaintext)];
    unsigned long long decrypted_len;
    crypto_aead_chacha20poly1305_ietf_decrypt(
        decrypted, &decrypted_len,
        NULL,
        ciphertext, ciphertext_len,
        ad, sizeof(ad),
        nonce, key
    );
    
    // AES-256-GCM
    if (crypto_aead_aes256gcm_is_available()) {
        unsigned char aes_key[crypto_aead_aes256gcm_KEYBYTES];
        unsigned char aes_nonce[crypto_aead_aes256gcm_NPUBBYTES];
        unsigned char aes_ciphertext[sizeof(plaintext) + crypto_aead_aes256gcm_ABYTES];
        
        crypto_aead_aes256gcm_keygen(aes_key);
        randombytes_buf(aes_nonce, sizeof(aes_nonce));
        
        crypto_aead_aes256gcm_encrypt(
            aes_ciphertext, &ciphertext_len,
            plaintext, sizeof(plaintext),
            ad, sizeof(ad),
            NULL, aes_nonce, aes_key
        );
        
        crypto_aead_aes256gcm_decrypt(
            decrypted, &decrypted_len,
            NULL,
            aes_ciphertext, ciphertext_len,
            ad, sizeof(ad),
            aes_nonce, aes_key
        );
    }
    
    // XChaCha20-Poly1305
    unsigned char xchacha_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char xchacha_nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned char xchacha_ciphertext[sizeof(plaintext) + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    
    crypto_aead_xchacha20poly1305_ietf_keygen(xchacha_key);
    randombytes_buf(xchacha_nonce, sizeof(xchacha_nonce));
    
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        xchacha_ciphertext, &ciphertext_len,
        plaintext, sizeof(plaintext),
        ad, sizeof(ad),
        NULL, xchacha_nonce, xchacha_key
    );
    
    crypto_aead_xchacha20poly1305_ietf_decrypt(
        decrypted, &decrypted_len,
        NULL,
        xchacha_ciphertext, ciphertext_len,
        ad, sizeof(ad),
        xchacha_nonce, xchacha_key
    );
}

void test_key_exchange() {
    // Curve25519 (X25519) - Key Exchange
    unsigned char alice_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char alice_sk[crypto_box_SECRETKEYBYTES];
    unsigned char bob_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char bob_sk[crypto_box_SECRETKEYBYTES];
    
    // Generate keypairs
    crypto_box_keypair(alice_pk, alice_sk);
    crypto_box_keypair(bob_pk, bob_sk);
    
    // Scalar multiplication (X25519)
    unsigned char shared_secret[crypto_scalarmult_BYTES];
    crypto_scalarmult(shared_secret, alice_sk, bob_pk);
    
    // Alternative: crypto_scalarmult_curve25519
    crypto_scalarmult_curve25519(shared_secret, alice_sk, bob_pk);
    
    // Box encryption (uses X25519 + XSalsa20-Poly1305)
    unsigned char nonce[crypto_box_NONCEBYTES];
    unsigned char message[] = "Secret message";
    unsigned char ciphertext[sizeof(message) + crypto_box_MACBYTES];
    
    randombytes_buf(nonce, sizeof(nonce));
    crypto_box_easy(ciphertext, message, sizeof(message), nonce, bob_pk, alice_sk);
    
    unsigned char decrypted[sizeof(message)];
    crypto_box_open_easy(decrypted, ciphertext, sizeof(ciphertext), nonce, alice_pk, bob_sk);
    
    // Key exchange API
    unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char server_sk[crypto_kx_SECRETKEYBYTES];
    
    crypto_kx_keypair(client_pk, client_sk);
    crypto_kx_keypair(server_pk, server_sk);
    
    unsigned char client_rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char client_tx[crypto_kx_SESSIONKEYBYTES];
    crypto_kx_client_session_keys(client_rx, client_tx, client_pk, client_sk, server_pk);
    
    unsigned char server_rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char server_tx[crypto_kx_SESSIONKEYBYTES];
    crypto_kx_server_session_keys(server_rx, server_tx, server_pk, server_sk, client_pk);
}

void test_digital_signatures() {
    // Ed25519 - Digital Signatures
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    
    // Generate keypair
    crypto_sign_keypair(pk, sk);
    
    // Alternative seed-based generation
    unsigned char seed[crypto_sign_SEEDBYTES];
    randombytes_buf(seed, sizeof(seed));
    crypto_sign_seed_keypair(pk, sk, seed);
    
    // Sign message
    unsigned char message[] = "Message to sign";
    unsigned char signed_message[crypto_sign_BYTES + sizeof(message)];
    unsigned long long signed_message_len;
    
    crypto_sign(signed_message, &signed_message_len, message, sizeof(message), sk);
    
    // Verify and open
    unsigned char unsigned_message[sizeof(message)];
    unsigned long long unsigned_message_len;
    crypto_sign_open(unsigned_message, &unsigned_message_len, 
                     signed_message, signed_message_len, pk);
    
    // Detached signatures
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, message, sizeof(message), sk);
    
    // Verify detached
    int valid = crypto_sign_verify_detached(sig, message, sizeof(message), pk);
    
    // Ed25519 specific functions
    crypto_sign_ed25519_keypair(pk, sk);
    crypto_sign_ed25519_seed_keypair(pk, sk, seed);
    crypto_sign_ed25519_detached(sig, NULL, message, sizeof(message), sk);
    crypto_sign_ed25519_verify_detached(sig, message, sizeof(message), pk);
}

void test_hash_functions() {
    unsigned char hash[crypto_hash_sha256_BYTES];
    const char *message = "Message to hash";
    
    // SHA-256
    crypto_hash_sha256(hash, (unsigned char*)message, strlen(message));
    
    // SHA-256 multi-part
    crypto_hash_sha256_state state256;
    crypto_hash_sha256_init(&state256);
    crypto_hash_sha256_update(&state256, (unsigned char*)message, strlen(message));
    crypto_hash_sha256_final(&state256, hash);
    
    // SHA-512
    unsigned char hash512[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(hash512, (unsigned char*)message, strlen(message));
    
    // SHA-512 multi-part
    crypto_hash_sha512_state state512;
    crypto_hash_sha512_init(&state512);
    crypto_hash_sha512_update(&state512, (unsigned char*)message, strlen(message));
    crypto_hash_sha512_final(&state512, hash512);
    
    // BLAKE2b
    unsigned char blake2b_hash[crypto_generichash_BYTES];
    crypto_generichash(blake2b_hash, sizeof(blake2b_hash),
                      (unsigned char*)message, strlen(message),
                      NULL, 0);
    
    // BLAKE2b with custom output length
    unsigned char blake2b_custom[64];
    crypto_generichash(blake2b_custom, sizeof(blake2b_custom),
                      (unsigned char*)message, strlen(message),
                      NULL, 0);
    
    // BLAKE2b multi-part
    crypto_generichash_state blake_state;
    crypto_generichash_init(&blake_state, NULL, 0, crypto_generichash_BYTES);
    crypto_generichash_update(&blake_state, (unsigned char*)message, strlen(message));
    crypto_generichash_final(&blake_state, blake2b_hash, crypto_generichash_BYTES);
    
    // BLAKE2b specific
    crypto_generichash_blake2b(blake2b_hash, sizeof(blake2b_hash),
                               (unsigned char*)message, strlen(message),
                               NULL, 0);
    
    crypto_generichash_blake2b_init(&blake_state, NULL, 0, crypto_generichash_BYTES);
    crypto_generichash_blake2b_update(&blake_state, (unsigned char*)message, strlen(message));
    crypto_generichash_blake2b_final(&blake_state, blake2b_hash, crypto_generichash_BYTES);
}

void test_mac_functions() {
    unsigned char key[crypto_auth_KEYBYTES];
    unsigned char mac[crypto_auth_BYTES];
    const char *message = "Message to authenticate";
    
    crypto_auth_keygen(key);
    
    // HMAC-SHA512-256 (default auth)
    crypto_auth(mac, (unsigned char*)message, strlen(message), key);
    int valid = crypto_auth_verify(mac, (unsigned char*)message, strlen(message), key);
    
    // HMAC-SHA256
    unsigned char hmac256_key[crypto_auth_hmacsha256_KEYBYTES];
    unsigned char hmac256[crypto_auth_hmacsha256_BYTES];
    
    crypto_auth_hmacsha256_keygen(hmac256_key);
    crypto_auth_hmacsha256(hmac256, (unsigned char*)message, strlen(message), hmac256_key);
    crypto_auth_hmacsha256_verify(hmac256, (unsigned char*)message, strlen(message), hmac256_key);
    
    // HMAC-SHA256 multi-part
    crypto_auth_hmacsha256_state hmac256_state;
    crypto_auth_hmacsha256_init(&hmac256_state, hmac256_key);
    crypto_auth_hmacsha256_update(&hmac256_state, (unsigned char*)message, strlen(message));
    crypto_auth_hmacsha256_final(&hmac256_state, hmac256);
    
    // HMAC-SHA512
    unsigned char hmac512_key[crypto_auth_hmacsha512_KEYBYTES];
    unsigned char hmac512[crypto_auth_hmacsha512_BYTES];
    
    crypto_auth_hmacsha512_keygen(hmac512_key);
    crypto_auth_hmacsha512(hmac512, (unsigned char*)message, strlen(message), hmac512_key);
    crypto_auth_hmacsha512_verify(hmac512, (unsigned char*)message, strlen(message), hmac512_key);
    
    // HMAC-SHA512 multi-part
    crypto_auth_hmacsha512_state hmac512_state;
    crypto_auth_hmacsha512_init(&hmac512_state, hmac512_key);
    crypto_auth_hmacsha512_update(&hmac512_state, (unsigned char*)message, strlen(message));
    crypto_auth_hmacsha512_final(&hmac512_state, hmac512);
    
    // Poly1305
    unsigned char poly1305_key[crypto_onetimeauth_KEYBYTES];
    unsigned char poly1305_mac[crypto_onetimeauth_BYTES];
    
    crypto_onetimeauth_keygen(poly1305_key);
    crypto_onetimeauth(poly1305_mac, (unsigned char*)message, strlen(message), poly1305_key);
    crypto_onetimeauth_verify(poly1305_mac, (unsigned char*)message, strlen(message), poly1305_key);
    
    // Poly1305 multi-part
    crypto_onetimeauth_state poly_state;
    crypto_onetimeauth_init(&poly_state, poly1305_key);
    crypto_onetimeauth_update(&poly_state, (unsigned char*)message, strlen(message));
    crypto_onetimeauth_final(&poly_state, poly1305_mac);
    
    // BLAKE2b keyed (MAC mode)
    unsigned char blake2b_key[crypto_generichash_KEYBYTES];
    unsigned char blake2b_mac[crypto_generichash_BYTES];
    
    crypto_generichash_keygen(blake2b_key);
    crypto_generichash(blake2b_mac, sizeof(blake2b_mac),
                      (unsigned char*)message, strlen(message),
                      blake2b_key, sizeof(blake2b_key));
    
    // BLAKE2b keyed multi-part
    crypto_generichash_state blake_state;
    crypto_generichash_init(&blake_state, blake2b_key, sizeof(blake2b_key), crypto_generichash_BYTES);
    crypto_generichash_update(&blake_state, (unsigned char*)message, strlen(message));
    crypto_generichash_final(&blake_state, blake2b_mac, crypto_generichash_BYTES);
}

int main() {
    // Initialize libsodium
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }
    
    test_secretbox();
    test_aead_algorithms();
    test_key_exchange();
    test_digital_signatures();
    test_hash_functions();
    test_mac_functions();
    
    std::cout << "All tests completed" << std::endl;
    return 0;
}
