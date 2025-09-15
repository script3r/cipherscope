package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

func main() {
	fmt.Println("Testing Go standard library crypto...")

	// RSA key generation
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	fmt.Println("✓ RSA 2048-bit key pair generated")

	// ECDSA key generation (P-256)
	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	fmt.Println("✓ ECDSA P-256 key pair generated")

	// AES encryption
	aesKey := make([]byte, 32) // 256-bit key
	rand.Read(aesKey)
	
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err)
	}

	// AES-GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	plaintext := []byte("Hello, Go Crypto World!")
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	fmt.Println("✓ AES-256-GCM encryption successful")

	// Hash functions
	sha256Hash := sha256.Sum256(plaintext)
	sha512Hash := sha512.Sum512(plaintext)
	
	fmt.Printf("✓ SHA-256 hash: %x\n", sha256Hash[:8])
	fmt.Printf("✓ SHA-512 hash: %x\n", sha512Hash[:8])

	fmt.Println("\nPQC Assessment:")
	fmt.Println("- RSA 2048-bit: VULNERABLE to quantum attacks")
	fmt.Println("- ECDSA P-256: VULNERABLE to quantum attacks") 
	fmt.Println("- AES-256-GCM: SAFE from quantum attacks")
	fmt.Println("- SHA-256: SAFE from quantum attacks")
	fmt.Println("- SHA-512: SAFE from quantum attacks")
}