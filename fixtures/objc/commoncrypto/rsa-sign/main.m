#import <Foundation/Foundation.h>
#import <Security/Security.h>

int main() {
    @autoreleasepool {
        NSData *message = [@"Hello, World!" dataUsingEncoding:NSUTF8StringEncoding];
        
        // Generate RSA key pair
        NSDictionary *parameters = @{
            (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
            (__bridge id)kSecAttrKeySizeInBits: @2048
        };
        
        SecKeyRef privateKey, publicKey;
        SecKeyGeneratePair((__bridge CFDictionaryRef)parameters, &publicKey, &privateKey);
        
        // Sign
        CFErrorRef error = NULL;
        NSData *signature = (__bridge_transfer NSData *)SecKeyCreateSignature(
            privateKey,
            kSecKeyAlgorithmRSASignatureMessagePSSSHA256,
            (__bridge CFDataRef)message,
            &error
        );
        
        // Verify
        Boolean valid = SecKeyVerifySignature(
            publicKey,
            kSecKeyAlgorithmRSASignatureMessagePSSSHA256,
            (__bridge CFDataRef)message,
            (__bridge CFDataRef)signature,
            &error
        );
        
        CFRelease(privateKey);
        CFRelease(publicKey);
    }
    return 0;
}
