package main

import (
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
)

func main() {
    // Generate key pair
    privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
    publicKey := &privateKey.PublicKey
    
    message := []byte("Hello, World!")
    hash := sha256.Sum256(message)
    
    // Sign
    signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
    
    // Verify
    err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature)
    _ = err
}
