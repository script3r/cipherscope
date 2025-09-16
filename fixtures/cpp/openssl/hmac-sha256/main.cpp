#include <openssl/hmac.h>
#include <string.h>

int main() {
    unsigned char key[] = "secret_key";
    unsigned char message[] = "Hello, World!";
    unsigned char mac[32];
    unsigned int mac_len;
    
    // Create HMAC
    HMAC(EVP_sha256(), key, strlen((char*)key), 
         message, strlen((char*)message), 
         mac, &mac_len);
    
    // Verify HMAC (compare with expected)
    unsigned char expected_mac[32];
    unsigned int expected_len;
    HMAC(EVP_sha256(), key, strlen((char*)key),
         message, strlen((char*)message),
         expected_mac, &expected_len);
    
    return memcmp(mac, expected_mac, mac_len) == 0 ? 0 : 1;
}
