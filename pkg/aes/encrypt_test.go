package aes

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestEncryptDecryptAESGCM(t *testing.T) {
	// Generate a 32-byte key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("Veera is the best!")
	fmt.Println("Plaintext: ", string(plaintext))
	fmt.Println("Key (Hex): ", hex.EncodeToString(key))

	// Encrypt
	encrypted, err := EncryptAESGCM(key, plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	fmt.Println("Encrypted (base64): ", encrypted)

	// Verify it's base64 encoded
	_, err = base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		t.Fatalf("Encrypted data is not valid base64: %v", err)
	}

	// Decrypt
	decrypted, err := DecryptAESGCM(key, encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify plaintext matches
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("Decrypted text does not match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

func TestEncryptAESGCM_InvalidKeySize(t *testing.T) {
	key := make([]byte, 16) // Wrong size
	plaintext := []byte("test")

	_, err := EncryptAESGCM(key, plaintext)
	if err == nil {
		t.Fatal("Expected error for invalid key size, got nil")
	}
}

func TestDecryptAESGCM_InvalidKeySize(t *testing.T) {
	key := make([]byte, 16) // Wrong size
	encrypted := "dGVzdA==" // dummy base64

	_, err := DecryptAESGCM(key, encrypted)
	if err == nil {
		t.Fatal("Expected error for invalid key size, got nil")
	}
}

func TestDecryptAESGCM_InvalidBase64(t *testing.T) {
	key := make([]byte, 32)
	encrypted := "not-valid-base64!!!"

	_, err := DecryptAESGCM(key, encrypted)
	if err == nil {
		t.Fatal("Expected error for invalid base64, got nil")
	}
}

func TestEncryptAESGCM_EmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte{}

	encrypted, err := EncryptAESGCM(key, plaintext)
	if err != nil {
		t.Fatalf("Encryption of empty plaintext failed: %v", err)
	}

	decrypted, err := DecryptAESGCM(key, encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatalf("Expected empty decrypted text, got %d bytes", len(decrypted))
	}
}
