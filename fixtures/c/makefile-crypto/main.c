#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>

int main() {
    // Basic OpenSSL usage
    OpenSSL_add_all_algorithms();
    
    // RSA key generation
    EVP_PKEY_CTX *rsa_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(rsa_ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(rsa_ctx, 2048);
    
    printf("Basic crypto setup with OpenSSL\n");
    printf("RSA 2048-bit key generation configured\n");
    
    EVP_PKEY_CTX_free(rsa_ctx);
    EVP_cleanup();
    
    return 0;
}