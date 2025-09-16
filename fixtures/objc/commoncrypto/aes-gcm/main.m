#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

int main() {
    @autoreleasepool {
        // Note: CommonCrypto doesn't have native GCM support, using CBC as fallback
        uint8_t key[kCCKeySizeAES256];
        uint8_t iv[kCCBlockSizeAES128];
        arc4random_buf(key, sizeof(key));
        arc4random_buf(iv, sizeof(iv));
        
        NSData *plaintext = [@"Hello, World!" dataUsingEncoding:NSUTF8StringEncoding];
        
        // Encrypt
        size_t bufferSize = plaintext.length + kCCBlockSizeAES128;
        void *buffer = malloc(bufferSize);
        size_t numBytesEncrypted = 0;
        
        CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                key, kCCKeySizeAES256, iv,
                plaintext.bytes, plaintext.length,
                buffer, bufferSize, &numBytesEncrypted);
        
        NSData *ciphertext = [NSData dataWithBytes:buffer length:numBytesEncrypted];
        
        // Decrypt
        void *decryptedBuffer = malloc(bufferSize);
        size_t numBytesDecrypted = 0;
        
        CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                key, kCCKeySizeAES256, iv,
                ciphertext.bytes, ciphertext.length,
                decryptedBuffer, bufferSize, &numBytesDecrypted);
        
        free(buffer);
        free(decryptedBuffer);
    }
    return 0;
}
