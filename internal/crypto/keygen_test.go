// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package crypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"
)

func TestKeygen(t *testing.T) {
	pk := make([]byte, 32)
	_, err := rand.Read(pk)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := X25519(pk)
	if err != nil {
		t.Fatal(err)
	}
	privateBytes, err := base64.StdEncoding.DecodeString(kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	// Check if this is an x25519 private key
	_, err = ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
}

func ECDSAP256Legacy(secret []byte) (*ecdsa.PrivateKey, error) {
	curve := elliptic.P256()
	d := new(big.Int).SetBytes(secret[:])
	n := curve.Params().N
	// Ensure 0 < d < N (N is the order of the curve)
	d.Mod(d, new(big.Int).Sub(n, big.NewInt(1)))
	d.Add(d, big.NewInt(1)) // make sure d != 0
	// Calculate the public key: Q = d * G
	x, y := curve.ScalarBaseMult(d.Bytes())
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}
	return priv, nil
}

func TestDeterministicECDSA(t *testing.T) {
	// Generate random 32 byte secret
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	if err != nil {
		t.Fatal(err)
	}

	kp1, err := ECDSA(secret, elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Private Key 1:", kp1.D)
	fmt.Println("Public Key 1:", kp1.PublicKey)

	kp2, err := ECDSAP256Legacy(secret)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Private Key 2:", kp2.D)
	fmt.Println("Public Key 2:", kp2.PublicKey)
	if kp1.D.Cmp(kp2.D) != 0 {
		t.Fatal("private keys do not match")
	}
	if kp1.PublicKey.X.Cmp(kp2.PublicKey.X) != 0 || kp1.PublicKey.Y.Cmp(kp2.PublicKey.Y) != 0 {
		t.Fatal("public keys do not match")
	}
}
