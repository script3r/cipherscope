#include <sodium.h>

int main() {
    if (sodium_init() < 0) return 1;
    
    unsigned char message[] = "Hello, World!";
    unsigned char hash[crypto_hash_sha256_BYTES];
    
    crypto_hash_sha256(hash, message, sizeof(message));
    
    return 0;
}
