#include <openssl/evp.h>
#include <string.h>

int main(){
	unsigned char key[32]; memset(key, 0x11, sizeof(key));
	unsigned char iv[12]; memset(iv, 0x22, sizeof(iv));
	unsigned char pt[5] = { 'h','e','l','l','o' };
	unsigned char ct[32]; int len=0, outlen=0;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL);
	EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
	EVP_EncryptUpdate(ctx, ct, &len, pt, sizeof(pt)); outlen = len;
	unsigned char tag[16];
	EVP_EncryptFinal_ex(ctx, ct+outlen, &len);
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}
