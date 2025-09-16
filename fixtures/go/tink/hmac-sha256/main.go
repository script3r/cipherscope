package main

import (
    "github.com/google/tink/go/mac"
    "github.com/google/tink/go/keyset"
)

func main() {
    // Initialize
    mac.Init()
    
    // Generate key
    kh, _ := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
    
    // Get primitive
    m, _ := mac.New(kh)
    
    message := []byte("Hello, World!")
    
    // Create MAC
    tag, _ := m.ComputeMAC(message)
    
    // Verify MAC
    _ = m.VerifyMAC(tag, message)
}
