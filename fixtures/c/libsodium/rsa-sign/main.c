#include <sodium.h>

int main() {
    if (sodium_init() < 0) return 1;
    
    // Note: libsodium doesn't support RSA, using Ed25519 instead
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    unsigned char message[] = "Hello, World!";
    unsigned char signed_message[crypto_sign_BYTES + sizeof(message)];
    unsigned char unsigned_message[sizeof(message)];
    unsigned long long signed_message_len, unsigned_message_len;
    
    // Generate key pair
    crypto_sign_keypair(pk, sk);
    
    // Sign
    crypto_sign(signed_message, &signed_message_len,
                message, sizeof(message), sk);
    
    // Verify
    int valid = crypto_sign_open(unsigned_message, &unsigned_message_len,
                                  signed_message, signed_message_len, pk);
    
    return valid;
}
