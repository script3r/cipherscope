#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <iostream>

int main() {
    std::cout << "Bazel C++ Module: OpenSSL crypto" << std::endl;
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (ctx) {
        std::cout << "RSA context created successfully" << std::endl;
        EVP_PKEY_CTX_free(ctx);
    }
    
    return 0;
}