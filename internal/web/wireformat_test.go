// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package web

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// Golden values for the KDS key-exchange bindings.
//
// These are wire formats shared with external TDX clients: the client computes
// the report data and this server recomputes it, so a change breaks every
// deployed client in a way the round-trip tests cannot catch - those pass as
// long as both halves of the test change together. Captured from the original
// longhand implementations before the hash helpers were extracted into
// internal/crypto; only change alongside a scheme version bump
// (kdsKeyExchangeScheme / sealKeyExchangeScheme).
func kdsTestVector() (pub, nonce []byte) {
	pub = make([]byte, 32)
	nonce = make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i)
		nonce[i] = byte(0x40 + i)
	}
	return pub, nonce
}

func TestKdsBindingsAreWireStable(t *testing.T) {
	pub, nonce := kdsTestVector()

	t.Run("kdsRequestBinding", func(t *testing.T) {
		require.Equal(t,
			"d22736b3bfba01f0b92312b8ae404df74fac70f74b829f85e60515a0c38989af"+
				"f9cd7bced62f4bf99921c1b38ccbd2b5fb1369fe9b7ef7abe81264cf227f8919",
			hex.EncodeToString(kdsRequestBinding(nonce, pub)))
	})

	t.Run("sealOfferBinding", func(t *testing.T) {
		require.Equal(t,
			"62baa48136a0fa74d4e6e8d318ee46a1f6f0052e600350c42fb57e2acc79b7ad"+
				"e1cb313a18f46193d55616a605b7ba5b2ae95d698cc948e62ef35b8da499cb45",
			hex.EncodeToString(sealOfferBinding(nonce, pub)))
	})

	t.Run("sealRequestBinding", func(t *testing.T) {
		require.Equal(t,
			"08120d432fd42c00fee560db06f4ba90dac0acbfd1c215befa0813987fc08f8a"+
				"0a0eff24a69a6aa75956ba0ed3fa66ad801f4c95a4b3cbf3f623c46ecc361e49",
			hex.EncodeToString(sealRequestBinding(nonce, pub)))
	})

	t.Run("kdsTranscript", func(t *testing.T) {
		require.Equal(t,
			"f636f5312c67b80f5f30f8d0be6b2074f36ce503cca295acb60d0bda0916401b",
			hex.EncodeToString(kdsTranscript(pub, nonce, pub)))
	})
}
