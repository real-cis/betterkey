// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestECDSASign(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	data := []byte("test message long message")
	signature, err := ECDSASign(privateKey, data)
	if err != nil {
		t.Fatalf("ECDSASign failed: %v", err)
	}
	if len(signature) == 0 {
		t.Fatal("signature is empty")
	}
	t.Logf("ECDSASign produced signature of length %d", len(signature))
}

func TestECDSASignAndVerify(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	data := []byte("test message long message")
	signature, err := ECDSASign(privateKey, data)
	if err != nil {
		t.Fatalf("ECDSASign failed: %v", err)
	}
	valid, err := ECDSAVerify(&privateKey.PublicKey, data, signature)
	if err != nil {
		t.Fatalf("ECDSAVerify failed: %v", err)
	}
	if !valid {
		t.Fatal("signature verification failed for valid signature")
	}
	t.Log("Valid signature verified successfully")
}
