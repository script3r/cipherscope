#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

int main() {
    unsigned char key[32];
    unsigned char iv[12];
    unsigned char tag[16];
    unsigned char plaintext[] = "Hello, World!";
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int len, ciphertext_len, decrypted_len;
    
    // Generate random key and IV
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));
    
    // Encrypt
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen((char*)plaintext));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    
    // Decrypt
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, decrypted, &len, ciphertext, ciphertext_len);
    decrypted_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    EVP_DecryptFinal_ex(ctx, decrypted + len, &len);
    
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
