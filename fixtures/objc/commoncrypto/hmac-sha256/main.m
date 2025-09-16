#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

int main() {
    @autoreleasepool {
        NSData *key = [@"secret_key" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *message = [@"Hello, World!" dataUsingEncoding:NSUTF8StringEncoding];
        uint8_t mac[CC_SHA256_DIGEST_LENGTH];
        
        CCHmac(kCCHmacAlgSHA256, key.bytes, key.length, 
               message.bytes, message.length, mac);
    }
    return 0;
}
