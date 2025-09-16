#import <Foundation/Foundation.h>
#include <openssl/hmac.h>

int main() {
    unsigned char key[] = "secret_key";
    unsigned char message[] = "Hello, World!";
    unsigned char mac[32];
    unsigned int mac_len;
    
    // Create HMAC
    HMAC(EVP_sha256(), key, strlen((char*)key), 
         message, strlen((char*)message), 
         mac, &mac_len);
    
    return 0;
}
