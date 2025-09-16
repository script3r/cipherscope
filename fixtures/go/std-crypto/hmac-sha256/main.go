package main

import (
    "crypto/hmac"
    "crypto/sha256"
)

func main() {
    key := []byte("secret_key")
    message := []byte("Hello, World!")
    
    // Create HMAC
    h := hmac.New(sha256.New, key)
    h.Write(message)
    mac := h.Sum(nil)
    
    // Verify HMAC
    h2 := hmac.New(sha256.New, key)
    h2.Write(message)
    expectedMac := h2.Sum(nil)
    
    valid := hmac.Equal(mac, expectedMac)
    _ = valid
}
