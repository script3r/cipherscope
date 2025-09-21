#include <openssl/sha.h>
int main(){ unsigned char d[32]; SHA256(NULL, 0, d); return 0; }
