#import <Foundation/Foundation.h>
#import <Tink/Tink.h>
#import "objc/TINKConfig.h"
#import "objc/TINKKeysetHandle.h"
#import "objc/TINKAeadFactory.h"
#import "objc/TINKMacFactory.h"
#import "objc/TINKSignatureFactory.h"
#import "objc/TINKAeadKeyTemplate.h"
#import "objc/TINKMacKeyTemplate.h"
#import "objc/TINKSignatureKeyTemplate.h"

int main() {
    @autoreleasepool {
        NSError *error = nil;
        
        // Register Tink configuration
        if (![TINKConfig registerConfig:&error]) {
            NSLog(@"Failed to register config: %@", error);
            return 1;
        }
        
        // Test various AEAD algorithms
        
        // AES-GCM
        TINKAeadKeyTemplate *aesGcmTemplate = [[TINKAeadKeyTemplate alloc] 
            initWithKeyTemplate:TINKAes256Gcm error:&error];
        
        // AES-EAX
        TINKAeadKeyTemplate *aesEaxTemplate = [[TINKAeadKeyTemplate alloc]
            initWithKeyTemplate:TINKAes256Eax error:&error];
            
        // AES-CTR-HMAC
        TINKAeadKeyTemplate *aesCtrHmacTemplate = [[TINKAeadKeyTemplate alloc]
            initWithKeyTemplate:TINKAes256CtrHmacSha256 error:&error];
            
        // ChaCha20-Poly1305
        TINKAeadKeyTemplate *chachaTemplate = [[TINKAeadKeyTemplate alloc]
            initWithKeyTemplate:TINKChaCha20Poly1305 error:&error];
            
        // XChaCha20-Poly1305
        TINKAeadKeyTemplate *xchachaTemplate = [[TINKAeadKeyTemplate alloc]
            initWithKeyTemplate:TINKXChaCha20Poly1305 error:&error];
            
        // AES-GCM-SIV
        TINKAeadKeyTemplate *aesGcmSivTemplate = [[TINKAeadKeyTemplate alloc]
            initWithKeyTemplate:TINKAes256GcmSiv error:&error];
        
        // MAC algorithms
        
        // HMAC-SHA256
        TINKMacKeyTemplate *hmacTemplate = [[TINKMacKeyTemplate alloc]
            initWithKeyTemplate:TINKHmacSha256Tag256 error:&error];
            
        // AES-CMAC
        TINKMacKeyTemplate *cmacTemplate = [[TINKMacKeyTemplate alloc]
            initWithKeyTemplate:TINKAesCmac error:&error];
            
        // HMAC-SHA512
        TINKMacKeyTemplate *hmac512Template = [[TINKMacKeyTemplate alloc]
            initWithKeyTemplate:TINKHmacSha512Tag512 error:&error];
        
        // Signature algorithms
        
        // ECDSA-P256
        TINKSignatureKeyTemplate *ecdsaP256Template = [[TINKSignatureKeyTemplate alloc]
            initWithKeyTemplate:TINKEcdsaP256 error:&error];
            
        // ECDSA-P384
        TINKSignatureKeyTemplate *ecdsaP384Template = [[TINKSignatureKeyTemplate alloc]
            initWithKeyTemplate:TINKEcdsaP384Sha384 error:&error];
            
        // Ed25519
        TINKSignatureKeyTemplate *ed25519Template = [[TINKSignatureKeyTemplate alloc]
            initWithKeyTemplate:TINKEd25519 error:&error];
            
        // RSA-SSA-PSS
        TINKSignatureKeyTemplate *rsaPssTemplate = [[TINKSignatureKeyTemplate alloc]
            initWithKeyTemplate:TINKRsaSsaPss3072Sha256F4 error:&error];
            
        // RSA-SSA-PKCS1
        TINKSignatureKeyTemplate *rsaPkcs1Template = [[TINKSignatureKeyTemplate alloc]
            initWithKeyTemplate:TINKRsaSsaPkcs14096Sha512F4 error:&error];
        
        // Hybrid encryption
        // Note: These would require TINKHybridKeyTemplate which might not be available
        // Just referencing the constants for pattern matching
        id eciesTemplate = TINKEciesP256HkdfHmacSha256Aes128Gcm;
        id hpkeTemplate = TINKHpkeX25519HkdfSha256Aes256Gcm;
        
        NSLog(@"All templates created successfully");
    }
    return 0;
}
