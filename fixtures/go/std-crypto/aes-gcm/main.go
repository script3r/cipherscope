package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
)

func main() {
    key := make([]byte, 32)
    nonce := make([]byte, 12)
    rand.Read(key)
    rand.Read(nonce)
    
    plaintext := []byte("Hello, World!")
    
    // Encrypt
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
    
    // Decrypt
    decrypted, _ := gcm.Open(nil, nonce, ciphertext, nil)
    _ = decrypted
}
