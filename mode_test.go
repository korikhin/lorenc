package lorenz

import (
	"bytes"
	"os"
	"testing"
)

func TestFileEncryption(t *testing.T) {
	plaintext, err := os.ReadFile("testdata/plain_01.txt")
	if err != nil {
		t.Fatalf("Failed to read source file: %v", err)
	}

	key := []byte("123456789012345678")

	block, err := NewChainEnctypter(key)
	if err != nil {
		t.Fatalf("Failed to create encrypter: %v", err)
	}

	// PKCS7 padding
	padding := block.BlockSize() - (len(plaintext) % block.BlockSize())
	padtext := append(plaintext, bytes.Repeat([]byte{byte(padding)}, padding)...)

	ciphertext := make([]byte, len(padtext))
	block.CryptBlocks(ciphertext, padtext)

	if err := os.WriteFile("testdata/cipher_01.bin", ciphertext, 0644); err != nil {
		t.Fatalf("Error writing to destination file: %v", err)
	}

	t.Log("File encrypted successfully")
}

func TestFileDecryption(t *testing.T) {
	src, err := os.ReadFile("testdata/cipher_01.bin")
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	key := []byte("123456789012345678")

	block, err := NewChainDectypter(key)
	if err != nil {
		t.Fatalf("Failed to create decrypter: %v", err)
	}

	decrypted := make([]byte, len(src))
	block.CryptBlocks(decrypted, src)

	// PKCS7 padding
	if len(decrypted) > 0 {
		padding := int(decrypted[len(decrypted)-1])
		if padding > 0 && padding <= block.BlockSize() && len(decrypted) >= padding {
			decrypted = decrypted[:len(decrypted)-padding]
		}
	}

	if err := os.WriteFile("testdata/plain_01_de.txt", decrypted, 0644); err != nil {
		t.Fatalf("Error writing to destination file: %v", err)
	}

	t.Log("File decrypted successfully")
}
