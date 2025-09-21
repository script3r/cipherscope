#include <openssl/rsa.h>
#include <openssl/pem.h>
int main(){ RSA *r = RSA_new(); BIGNUM *b = BN_new(); BN_set_word(b, RSA_F4); RSA_generate_key_ex(r, 2048, b, NULL); return 0; }
