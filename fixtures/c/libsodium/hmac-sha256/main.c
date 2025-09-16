#include <sodium.h>

int main() {
    if (sodium_init() < 0) return 1;
    
    unsigned char key[crypto_auth_hmacsha256_KEYBYTES];
    unsigned char message[] = "Hello, World!";
    unsigned char mac[crypto_auth_hmacsha256_BYTES];
    
    // Generate key
    crypto_auth_hmacsha256_keygen(key);
    
    // Create HMAC
    crypto_auth_hmacsha256(mac, message, sizeof(message), key);
    
    // Verify HMAC
    int valid = crypto_auth_hmacsha256_verify(mac, message, sizeof(message), key);
    
    return valid;
}
