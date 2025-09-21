package main

import (
	"fmt"
	"log"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
)

func main() {
	// Initialize AEAD
	aead.Init()
	mac.Init()
	signature.Init()

	// Generate a new AES256-GCM keyset
	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		log.Fatal(err)
	}

	// Get AEAD primitive
	a, err := aead.New(kh)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt
	plaintext := []byte("Hello Tink Go")
	associatedData := []byte("metadata")
	ciphertext, err := a.Encrypt(plaintext, associatedData)
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt
	decrypted, err := a.Decrypt(ciphertext, associatedData)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Decrypted: %s\n", decrypted)

	// Also demonstrate AES-CTR-HMAC
	ctrHandle, err := keyset.NewHandle(aead.AES256CTRHMACSHA256KeyTemplate())
	if err != nil {
		log.Fatal(err)
	}
	ctrAead, err := aead.New(ctrHandle)
	if err != nil {
		log.Fatal(err)
	}

	// And ChaCha20-Poly1305
	chachaHandle, err := keyset.NewHandle(aead.ChaCha20Poly1305KeyTemplate())
	if err != nil {
		log.Fatal(err)
	}
	chachaAead, err := aead.New(chachaHandle)
	if err != nil {
		log.Fatal(err)
	}

	// Use them
	_, _ = ctrAead.Encrypt(plaintext, nil)
	_, _ = chachaAead.Encrypt(plaintext, nil)

	// HMAC example
	hmacHandle, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
	if err != nil {
		log.Fatal(err)
	}
	m, err := mac.New(hmacHandle)
	if err != nil {
		log.Fatal(err)
	}
	tag, _ := m.ComputeMAC(plaintext)
	fmt.Printf("HMAC tag length: %d\n", len(tag))
}
