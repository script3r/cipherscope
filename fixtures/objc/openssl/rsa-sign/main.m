#import <Foundation/Foundation.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

int main() {
    // Generate RSA key pair
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bn, NULL);
    
    unsigned char message[] = "Hello, World!";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    
    // Hash the message
    SHA256(message, strlen((char*)message), hash);
    
    // Sign
    unsigned char signature[256];
    unsigned int sig_len;
    RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, 
             signature, &sig_len, rsa);
    
    // Verify
    int valid = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH,
                          signature, sig_len, rsa);
    
    RSA_free(rsa);
    BN_free(bn);
    
    return valid ? 0 : 1;
}
