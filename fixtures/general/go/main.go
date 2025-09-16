package main

import (
	"crypto/aes"
	"crypto/cipher"
)

func main() {
	block, _ := aes.NewCipher(make([]byte, 16))
	cipher.NewGCM(block)
}
