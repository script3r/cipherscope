package main

import (
    "crypto/sha256"
)

func main() {
    message := []byte("Hello, World!")
    hash := sha256.Sum256(message)
    _ = hash
}
