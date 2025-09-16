package main

import (
    "github.com/google/tink/go/signature"
    "github.com/google/tink/go/keyset"
)

func main() {
    // Initialize
    signature.Init()
    
    // Generate key pair
    privateKH, _ := keyset.NewHandle(signature.RSA_PSS_3072_SHA256_F4_KeyTemplate())
    publicKH, _ := privateKH.Public()
    
    // Get primitives
    signer, _ := signature.NewSigner(privateKH)
    verifier, _ := signature.NewVerifier(publicKH)
    
    message := []byte("Hello, World!")
    
    // Sign
    sig, _ := signer.Sign(message)
    
    // Verify
    _ = verifier.Verify(sig, message)
}
