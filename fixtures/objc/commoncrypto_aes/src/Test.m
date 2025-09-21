#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

int main() {
    NSData *key = [@"12345678901234567890123456789012" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *iv = [@"1234567890123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [@"Hello World" dataUsingEncoding:NSUTF8StringEncoding];
    
    NSMutableData *encrypted = [NSMutableData dataWithLength:data.length + kCCBlockSizeAES128];
    size_t numBytesEncrypted = 0;
    
    CCCryptorStatus status = CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                                     key.bytes, key.length, iv.bytes,
                                     data.bytes, data.length,
                                     encrypted.mutableBytes, encrypted.length,
                                     &numBytesEncrypted);
    
    if (status == kCCSuccess) {
        encrypted.length = numBytesEncrypted;
        NSLog(@"Encrypted: %@", encrypted);
    }
    
    return 0;
}
