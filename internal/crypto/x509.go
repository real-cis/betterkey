// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package crypto

import (
	"crypto/sha256"
	"crypto/x509"
)

func HashPublicKey(pub any) ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	result := sha256.Sum256(pubBytes)
	return result[:], nil
}
