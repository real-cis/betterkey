// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package cluster

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// Golden values for the cluster key-exchange bindings.
//
// These are wire formats: a node computes them and a peer recomputes them
// independently, so any change breaks interoperability with already-deployed
// nodes in ways the round-trip tests cannot catch - those pass as long as both
// sides change together. The constants below were captured from the original
// longhand implementations before the hash helpers were extracted into
// internal/crypto, and must only change alongside a protocol version bump.
func testVector() (pub, nonce []byte) {
	pub = make([]byte, 32)
	nonce = make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i)
		nonce[i] = byte(0x40 + i)
	}
	return pub, nonce
}

func TestClusterBindingsAreWireStable(t *testing.T) {
	pub, nonce := testVector()

	t.Run("kxRequestBinding", func(t *testing.T) {
		require.Equal(t,
			"5b95289145730b633c2a1870382b20f9a197ed5f92b7103ccc5caad276dc5476"+
				"a60d970ce839a722e6151acf96f66f79a5215fdb31730c74ec1f3fd78c9ef565",
			hex.EncodeToString(kxRequestBinding(pub, nonce)))
	})

	t.Run("seedOfferBinding", func(t *testing.T) {
		require.Equal(t,
			"38fa84b1c40a262a7728bac1b6725d30ff0099bdc79c5878b8c57c3ec6a0d704"+
				"cfa363d7d0cf82afa809d8e4639288b837b029ffd23a4693ec174dbc20f2acaa",
			hex.EncodeToString(seedOfferBinding("cluster-x", pub, nonce)))
	})

	t.Run("kxTranscript", func(t *testing.T) {
		require.Equal(t,
			"0225ac7f60e8458c16c9b203428cbe5e73a6904cf3df49ee680c0186f272b6bb",
			hex.EncodeToString(kxTranscript(pub, nonce, pub, nonce)))
	})
}
