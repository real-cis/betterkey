// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package db

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"gitlab.com/real-cis/cc/betterkey/internal/common"
)

type noopVault struct{}

func (s *noopVault) Seal(data []byte) ([]byte, error) {
	return data, nil
}
func (s *noopVault) Unseal(data []byte) ([]byte, error) {
	return data, nil
}
func (s *noopVault) HKDF(data []byte, info string, length int) ([]byte, error) {
	return data, nil
}

func TestWriteReadDelete(t *testing.T) {
	k := "key"
	v := "value"

	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "valkey/valkey:8.0.2-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForLog("Ready to accept connections"),
	}
	valkeyContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})

	defer testcontainers.CleanupContainer(t, valkeyContainer)
	require.NoError(t, err)

	valkeyEp, _ := valkeyContainer.Endpoint(ctx, "")
	valkeyUri := []string{valkeyEp}

	var nodeEnc common.Vault = &noopVault{}
	prov := func() common.Vault {
		return nodeEnc
	}

	vk, err := NewValKeyKeyService(valkeyUri, "default", "", "TEST", false, prov)
	if err != nil {
		t.Fatal(err)
	}
	err = vk.Write(k, []byte(v))
	if err != nil {
		t.Fatal(err)
	}

	vb, err := vk.Read(k)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(vb, []byte(v)) {
		t.Fatal(fmt.Errorf("mismatch, expect %0b, got %0b", []byte(v), vb))
	}
	err = vk.Delete(k)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := vk.Read(k)
	if len(n) > 0 {
		t.Fatal(fmt.Errorf("mismatch, expect nothing, got %0b", n))
	}
}
