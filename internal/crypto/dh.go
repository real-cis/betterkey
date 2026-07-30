// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

// Primitives shared by the attested key exchanges: cluster master-key transfer
// (join and seeding) and the KDS key-delivery and seal flows.
//
// Only the mechanical parts live here - key generation, ECDH, and the hash
// shapes. Each protocol keeps its own labels, transcript composition and
// attestation rules, because those are what make the exchanges distinct and
// what stops material from one being replayed into another.

// PublicKeyLen is the size of an X25519 public key. Fixed-length keys keep the
// hashed concatenations in protocol bindings unambiguous.
const PublicKeyLen = 32

// Ephemeral is a single-use X25519 key pair. The private half stays inside this
// process; protocols that must persist it are responsible for protecting it.
type Ephemeral struct {
	priv *ecdh.PrivateKey
}

// NewEphemeral generates a fresh key pair.
func NewEphemeral() (*Ephemeral, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral key failed: %w", err)
	}
	return &Ephemeral{priv: priv}, nil
}

// EphemeralFromBytes restores a key pair from a stored private key.
func EphemeralFromBytes(priv []byte) (*Ephemeral, error) {
	key, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("bad stored ephemeral key: %w", err)
	}
	return &Ephemeral{priv: key}, nil
}

// Public returns the public key to send to the peer.
func (e *Ephemeral) Public() []byte { return e.priv.PublicKey().Bytes() }

// PrivateBytes returns the private key for protocols that must persist it
// across requests. Callers must keep the result confidential.
func (e *Ephemeral) PrivateBytes() []byte { return e.priv.Bytes() }

// SharedSecret performs the Diffie-Hellman with a peer's public key.
func (e *Ephemeral) SharedSecret(peerPub []byte) ([]byte, error) {
	if err := ValidatePublicKey(peerPub); err != nil {
		return nil, err
	}
	peer, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("bad ephemeral public key: %w", err)
	}
	shared, err := e.priv.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("ecdh failed: %w", err)
	}
	return shared, nil
}

// ValidatePublicKey rejects a peer key of the wrong size.
func ValidatePublicKey(pub []byte) error {
	if len(pub) != PublicKeyLen {
		return fmt.Errorf("bad ephemeral public key length %d, want %d", len(pub), PublicKeyLen)
	}
	return nil
}

// LabeledHash512 returns SHA-512 over a domain-separating label and parts. Used
// for attestation report data, which is 64 bytes on both SGX and TDX.
func LabeledHash512(label string, parts ...[]byte) []byte {
	h := sha512.New()
	h.Write([]byte(label))
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// Transcript returns SHA-256 over parts, used as the HKDF salt binding a
// wrapping key to one exchange. Callers must pass fixed-length parts, or order
// them so the concatenation cannot be ambiguous.
func Transcript(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}
