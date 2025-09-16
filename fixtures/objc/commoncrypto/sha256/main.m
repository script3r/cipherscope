#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

int main() {
    @autoreleasepool {
        NSData *message = [@"Hello, World!" dataUsingEncoding:NSUTF8StringEncoding];
        uint8_t digest[CC_SHA256_DIGEST_LENGTH];
        
        CC_SHA256(message.bytes, (CC_LONG)message.length, digest);
    }
    return 0;
}
