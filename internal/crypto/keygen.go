// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package crypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

type KeyPair struct {
	Private string `json:"private"`
	Public  string `json:"public"`
}

func HKDF(key []byte, salt []byte, info []byte, length int) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, key, salt, info)
	secret := make([]byte, length)
	_, err := io.ReadFull(hkdf, secret)
	return secret, err
}

func X25519(keyBytes []byte) (*KeyPair, error) {
	ecdhKey, err := ecdh.X25519().NewPrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}

	return &KeyPair{Private: base64.StdEncoding.EncodeToString(ecdhKey.Bytes()),
		Public: base64.StdEncoding.EncodeToString(ecdhKey.PublicKey().Bytes())}, nil
}

func RSA() (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	return &KeyPair{Private: base64.StdEncoding.EncodeToString(privPEM),
		Public: base64.StdEncoding.EncodeToString(pubPEM)}, nil
}

func P256() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func P384() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

func ECDSA(keyBytes []byte, curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	var ecdhCurve ecdh.Curve
	switch curve {
	case elliptic.P256():
		ecdhCurve = ecdh.P256()
	case elliptic.P384():
		ecdhCurve = ecdh.P384()
	case elliptic.P521():
		ecdhCurve = ecdh.P521()
	default:
		return nil, fmt.Errorf(`unsupported curve %v`, curve)
	}
	n := curve.Params().N
	d := new(big.Int).SetBytes(keyBytes[:])
	// Ensure d is within valid range [1, n-1]
	d.Mod(d, new(big.Int).Sub(n, big.NewInt(1)))
	d.Add(d, big.NewInt(1)) // make sure d != 0

	ecdhPrivKey, err := ecdhCurve.NewPrivateKey(d.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to create ECDH private key: %w", err)
	}

	pubKeyBytes := ecdhPrivKey.PublicKey().Bytes()

	// Validate minimum 1 byte per coordinate, first byte is 0x04 (uncompressed)
	if len(pubKeyBytes) < 3 || pubKeyBytes[0] != 0x04 {
		return nil, fmt.Errorf("invalid public key format")
	}

	coordBytes := len(pubKeyBytes) - 1
	if coordBytes%2 != 0 {
		return nil, fmt.Errorf("invalid length: coordinates must be equal size")
	}

	keyLen := coordBytes / 2
	privateKey := &ecdsa.PrivateKey{
		D: d,
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(pubKeyBytes[1 : 1+keyLen]),
			Y:     new(big.Int).SetBytes(pubKeyBytes[1+keyLen:]),
		},
	}

	return privateKey, nil
}
