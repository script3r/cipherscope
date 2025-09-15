package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "fmt"
    "golang.org/x/crypto/chacha20poly1305"
)

func main() {
    // Generate RSA key pair
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        panic(err)
    }
    publicKey := &privateKey.PublicKey

    // Test message
    message := []byte("Hello, World!")

    // RSA encryption
    hash := sha256.New()
    ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, message, nil)
    if err != nil {
        panic(err)
    }

    // RSA decryption
    plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, ciphertext, nil)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Original: %s\n", message)
    fmt.Printf("Decrypted: %s\n", plaintext)

    // ChaCha20Poly1305 AEAD
    key := make([]byte, chacha20poly1305.KeySize)
    rand.Read(key)
    
    aead, err := chacha20poly1305.New(key)
    if err != nil {
        panic(err)
    }

    nonce := make([]byte, aead.NonceSize())
    rand.Read(nonce)

    ciphertext2 := aead.Seal(nil, nonce, message, nil)
    plaintext2, err := aead.Open(nil, nonce, ciphertext2, nil)
    if err != nil {
        panic(err)
    }

    fmt.Printf("ChaCha20Poly1305 - Original: %s\n", message)
    fmt.Printf("ChaCha20Poly1305 - Decrypted: %s\n", plaintext2)
}