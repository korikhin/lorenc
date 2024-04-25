package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

func main() {
	// Generate a new AES-256 key.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err.Error())
	}

	// Create a new GCM cipher using the AES key.
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	// Nonce should be unique for each encryption to be secure.
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	// Example plaintext data to encrypt.
	plaintext := []byte("Sensitive data that needs to be encrypted.")

	// Encrypt the data and append the tag for integrity checking.
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)
	fmt.Printf("Ciphertext: %x\n", ciphertext)

	// To decrypt and verify integrity, use the same nonce and key.
	decryptedText, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic("Failed to decrypt or data has been tampered with!")
	}
	fmt.Printf("Decrypted text: %s\n", decryptedText)
}
