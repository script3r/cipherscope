#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>
#import <openssl/evp.h>
#import <openssl/rsa.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // CommonCrypto usage
        const char *message = "Hello, World!";
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        
        CC_SHA256(message, (CC_LONG)strlen(message), digest);
        
        printf("SHA256: ");
        for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
            printf("%02x", digest[i]);
        }
        printf("\n");
        
        // OpenSSL usage
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        const EVP_MD *md = EVP_sha256();
        
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, message, strlen(message));
        
        unsigned int digest_len;
        EVP_DigestFinal_ex(mdctx, digest, &digest_len);
        EVP_MD_CTX_free(mdctx);
        
        printf("OpenSSL SHA256: ");
        for (unsigned int i = 0; i < digest_len; i++) {
            printf("%02x", digest[i]);
        }
        printf("\n");
    }
    return 0;
}
