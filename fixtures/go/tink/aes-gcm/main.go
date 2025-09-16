package main

import (
    "github.com/google/tink/go/aead"
    "github.com/google/tink/go/keyset"
)

func main() {
    // Initialize
    aead.Init()
    
    // Generate key
    kh, _ := keyset.NewHandle(aead.AES256GCMKeyTemplate())
    
    // Get primitive
    a, _ := aead.New(kh)
    
    plaintext := []byte("Hello, World!")
    associatedData := []byte{}
    
    // Encrypt
    ciphertext, _ := a.Encrypt(plaintext, associatedData)
    
    // Decrypt
    decrypted, _ := a.Decrypt(ciphertext, associatedData)
    _ = decrypted
}
