#include <openssl/evp.h>
#include <string.h>

int main(){
    unsigned char key[16]; memset(key, 0x11, sizeof(key));
    unsigned char iv[16]; memset(iv, 0x22, sizeof(iv));
    unsigned char pt[5] = { 'h','e','l','l','o' };
    unsigned char ct[32]; int len=0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ct, &len, pt, sizeof(pt));
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
