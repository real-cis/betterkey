// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package common

import (
	"encoding/hex"
	"sync"

	"github.com/edgelesssys/ego/ecrypto"
	"gitlab.com/real-cis/cc/betterkey/internal/crypto"
)

// Keystore interface for basic key-value operations
type BaseKeyStore interface {
	Read(id string) ([]byte, error)
	Write(id string, key []byte) error
	WriteWithTTL(id string, key []byte, ttl int) error
	Delete(id string) error
	Exists(id string) (int64, error)
	HasNil(err error) bool
}

// KeyStore with listing and stat capabilities
type KeyStore interface {
	BaseKeyStore
	List(prefix string, recursive bool) ([]string, error)
	Stat(id string) (*StorageStat, error)
	// atomically write value at id with a TTL only if id does not already exist.
	WriteNX(id string, value []byte, ttlSeconds int) (bool, error)
}

// All operations involving master secret
type Vault interface {
	Seal(data []byte) ([]byte, error)
	Unseal(data []byte) ([]byte, error)
	HKDF(data []byte, info string, length int) ([]byte, error)
}

// MasterKeyStore interface for managing master secrets
type MasterKeyStore interface {
	Read() *Member
	Write(secret *MasterSecret)
}

func (m *Member) Seal(data []byte) ([]byte, error) {
	k, err := hex.DecodeString(m.MasterSecret.Secret)
	if err != nil {
		return nil, err
	}
	return ecrypto.Encrypt(data, k, nil)
}

func (m *Member) Unseal(data []byte) ([]byte, error) {
	k, err := hex.DecodeString(m.MasterSecret.Secret)
	if err != nil {
		return nil, err
	}
	return ecrypto.Decrypt(data, k, nil)
}

func (m *Member) HKDF(data []byte, info string, length int) ([]byte, error) {
	k, err := hex.DecodeString(m.MasterSecret.Secret)
	if err != nil {
		return nil, err
	}
	return crypto.HKDF(k, data, []byte(info), length)
}

func NewCountDown(count int) *sync.WaitGroup {
	wg := &sync.WaitGroup{}
	wg.Add(count)
	return wg
}
