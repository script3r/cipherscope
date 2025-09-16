package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
)

func main() {
    key := make([]byte, 32)
    rand.Read(key)
    
    plaintext := []byte("Hello, World!")
    
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    
    nonce := make([]byte, gcm.NonceSize())
    rand.Read(nonce)
    
    // Encrypt
    ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
    
    // Decrypt
    decrypted, _ := gcm.Open(nil, nonce, ciphertext, nil)
    _ = decrypted
}
