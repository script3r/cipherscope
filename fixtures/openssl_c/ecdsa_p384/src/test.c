#include <openssl/ec.h>
int main(){ EC_KEY *k = EC_KEY_new_by_curve_name(NID_secp384r1); return 0; }
