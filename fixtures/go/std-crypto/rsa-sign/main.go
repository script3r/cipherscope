package main

import (
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
)

func main() {
    message := []byte("Hello, World!")
    
    // Generate RSA key pair
    privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
    publicKey := &privateKey.PublicKey
    
    // Sign
    hash := sha256.Sum256(message)
    signature, _ := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], nil)
    
    // Verify
    err := rsa.VerifyPSS(publicKey, crypto.SHA256, hash[:], signature, nil)
    _ = err
}
