#include <sodium.h>
#include <string.h>

int main() {
    if (sodium_init() < 0) return 1;
    
    unsigned char key[crypto_aead_aes256gcm_KEYBYTES];
    unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
    unsigned char plaintext[] = "Hello, World!";
    unsigned char ciphertext[sizeof(plaintext) + crypto_aead_aes256gcm_ABYTES];
    unsigned char decrypted[sizeof(plaintext)];
    unsigned long long ciphertext_len, decrypted_len;
    
    // Generate key and nonce
    crypto_aead_aes256gcm_keygen(key);
    randombytes_buf(nonce, sizeof(nonce));
    
    // Encrypt
    crypto_aead_aes256gcm_encrypt(ciphertext, &ciphertext_len,
                                   plaintext, sizeof(plaintext),
                                   NULL, 0, NULL, nonce, key);
    
    // Decrypt
    crypto_aead_aes256gcm_decrypt(decrypted, &decrypted_len,
                                   NULL, ciphertext, ciphertext_len,
                                   NULL, 0, nonce, key);
    
    return 0;
}
