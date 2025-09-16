#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <string.h>

int main() {
    unsigned char message[] = "Hello, World!";
    unsigned char signature[256];
    unsigned int sig_len;
    
    // Generate RSA key pair
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen(kctx, &pkey);
    EVP_PKEY_CTX_free(kctx);
    
    // Sign
    EVP_MD_CTX *sctx = EVP_MD_CTX_new();
    EVP_SignInit(sctx, EVP_sha256());
    EVP_SignUpdate(sctx, message, strlen((char*)message));
    EVP_SignFinal(sctx, signature, &sig_len, pkey);
    
    // Verify
    EVP_MD_CTX *vctx = EVP_MD_CTX_new();
    EVP_VerifyInit(vctx, EVP_sha256());
    EVP_VerifyUpdate(vctx, message, strlen((char*)message));
    int result = EVP_VerifyFinal(vctx, signature, sig_len, pkey);
    
    EVP_MD_CTX_free(sctx);
    EVP_MD_CTX_free(vctx);
    EVP_PKEY_free(pkey);
    
    return result == 1 ? 0 : 1;
}
