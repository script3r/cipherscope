#import <Foundation/Foundation.h>
#include <openssl/evp.h>

int main() {
    unsigned char key[32] = {0};
    unsigned char iv[12] = {0};
    unsigned char plaintext[] = "Hello, World!";
    unsigned char ciphertext[128];
    unsigned char tag[16];
    int len;
    int ciphertext_len;
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    // Encrypt
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen((char*)plaintext));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
