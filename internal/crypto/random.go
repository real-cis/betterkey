// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package crypto

import (
	"crypto/rand"
	"fmt"
	"io"
	"time"

	"github.com/hashicorp/go-uuid"
)

func GenerateNonce(len int) []byte {
	randomBytes := make([]byte, len)
	_, err := io.ReadFull(rand.Reader, randomBytes)
	if err != nil {
		panic(err)
	}
	return randomBytes
}

func GenerateUUID() string {
	id, err := uuid.GenerateUUID()
	if err != nil {
		panic(err)
	}
	return id
}

// GenerateSessionID returns a time-sortable session identifier of the form
// "<epoch-ms>.<uuid>".
func GenerateSessionID() string {
	return fmt.Sprintf("%013d.%s", time.Now().UnixMilli(), GenerateUUID())
}
