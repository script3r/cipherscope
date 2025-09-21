#import <Foundation/Foundation.h>
#import <Tink/Tink.h>
#import "objc/TINKConfig.h"
#import "objc/TINKKeysetHandle.h"
#import "objc/TINKAeadFactory.h"
#import "objc/TINKAeadKeyTemplate.h"

int main() {
    @autoreleasepool {
        NSError *error = nil;
        
        // Register Tink configuration
        if (![TINKConfig registerConfig:&error]) {
            NSLog(@"Failed to register config: %@", error);
            return 1;
        }
        
        // Generate new AES-GCM keyset
        TINKAeadKeyTemplate *template = [[TINKAeadKeyTemplate alloc] 
            initWithKeyTemplate:TINKAes256Gcm error:&error];
        if (!template) {
            NSLog(@"Failed to create template: %@", error);
            return 1;
        }
        
        TINKKeysetHandle *keysetHandle = [[TINKKeysetHandle alloc] 
            initWithKeyTemplate:template error:&error];
        if (!keysetHandle) {
            NSLog(@"Failed to generate keyset: %@", error);
            return 1;
        }
        
        // Get AEAD primitive
        id<TINKAead> aead = [TINKAeadFactory primitiveWithKeysetHandle:keysetHandle 
                                                                  error:&error];
        if (!aead) {
            NSLog(@"Failed to get primitive: %@", error);
            return 1;
        }
        
        // Encrypt
        NSData *plaintext = [@"Hello Tink ObjC" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *associatedData = [@"metadata" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *ciphertext = [aead encrypt:plaintext 
                         withAdditionalData:associatedData 
                                      error:&error];
        if (!ciphertext) {
            NSLog(@"Encryption failed: %@", error);
            return 1;
        }
        
        // Decrypt
        NSData *decrypted = [aead decrypt:ciphertext 
                        withAdditionalData:associatedData 
                                     error:&error];
        if (!decrypted) {
            NSLog(@"Decryption failed: %@", error);
            return 1;
        }
        
        NSString *result = [[NSString alloc] initWithData:decrypted 
                                                  encoding:NSUTF8StringEncoding];
        NSLog(@"Decrypted: %@", result);
    }
    return 0;
}
