#include <openssl/evp.h>
#include <stdio.h>

int main() {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    printf("%p\n", (void*)ctx);
    return 0;
}

