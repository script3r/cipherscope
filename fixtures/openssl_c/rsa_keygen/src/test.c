#include <openssl/rsa.h>
#include <openssl/pem.h>
int main(){ RSA *r = RSA_new(); BIGNUM *b = BN_new(); BN_set_word(b, RSA_F4); RSA_generate_key_ex(r, 2048, b, NULL); return 0; }

const int RSA_KEY_SIZE_CONST = 3072;
void test_const_keysize(){ RSA *r = RSA_new(); BIGNUM *b = BN_new(); BN_set_word(b, RSA_F4); RSA_generate_key_ex(r, RSA_KEY_SIZE_CONST, b, NULL); }
