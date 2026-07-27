// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package cluster

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/real-cis/cc/betterkey/internal/sgx"
)

// fakeAttestor models an enclave that signs report data: the quote *is* the
// report data, so verification reduces to exactly the binding check. That keeps
// the tests focused on whether the protocol binds quotes to key material,
// without needing a real enclave.
type fakeAttestor struct{}

func (fakeAttestor) Enabled() bool { return true }

func (fakeAttestor) Quote(reportData []byte) ([]byte, error) {
	return bytes.Clone(reportData), nil
}

func (fakeAttestor) VerifyQuote(quote, expected []byte) error {
	if len(quote) == 0 {
		return errors.New("peer supplied no quote")
	}
	if !bytes.Equal(quote, expected) {
		return errors.New("quote is not bound to this exchange")
	}
	return nil
}

func testMasterKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, masterKeyLen)
	_, err := rand.Read(k)
	require.NoError(t, err)
	return k
}

func TestKeyExchangeRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		attestor sgx.Attestor
	}{
		{"attested", fakeAttestor{}},
		// non-SGX build: the exchange must still work, just without quotes
		{"attestation disabled", sgx.NewAttestor(nil)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			secret := testMasterKey(t)

			req, pending, err := newKeyExchangeRequest(tc.attestor)
			require.NoError(t, err)

			resp, err := wrapMasterKey(tc.attestor, req, secret)
			require.NoError(t, err)

			// the master key must never appear on the wire
			raw, err := base64.StdEncoding.DecodeString(resp.WrappedKey)
			require.NoError(t, err)
			require.False(t, bytes.Contains(raw, secret), "master key leaked into the wrapped payload")

			got, err := unwrapMasterKey(tc.attestor, pending, resp)
			require.NoError(t, err)
			require.Equal(t, secret, got)
		})
	}
}

// A relay that swaps in its own ephemeral key while forwarding the victim's
// quote must be rejected: the quote is bound to the key it was minted for.
func TestKeyExchangeRejectsSubstitutedRequesterKey(t *testing.T) {
	attestor := fakeAttestor{}

	victim, _, err := newKeyExchangeRequest(attestor)
	require.NoError(t, err)

	attackerKey, _, err := newKxEphemeral()
	require.NoError(t, err)

	forged := &keyExchangeRequest{
		EphemeralPub: attackerKey.PublicKey().Bytes(),
		Nonce:        victim.Nonce,
		Quote:        victim.Quote,
	}
	_, err = wrapMasterKey(attestor, forged, testMasterKey(t))
	require.ErrorContains(t, err, "requester attestation rejected")
}

// Same property in the other direction: substituting the responder's ephemeral
// key invalidates the transcript the responder quote is bound to.
func TestKeyExchangeRejectsSubstitutedResponderKey(t *testing.T) {
	attestor := fakeAttestor{}

	req, pending, err := newKeyExchangeRequest(attestor)
	require.NoError(t, err)
	resp, err := wrapMasterKey(attestor, req, testMasterKey(t))
	require.NoError(t, err)

	attackerKey, _, err := newKxEphemeral()
	require.NoError(t, err)
	resp.EphemeralPub = attackerKey.PublicKey().Bytes()

	_, err = unwrapMasterKey(attestor, pending, resp)
	require.ErrorContains(t, err, "responder attestation rejected")
}

// A quote is valid for exactly one exchange.
func TestKeyExchangeRejectsQuoteFromAnotherExchange(t *testing.T) {
	attestor := fakeAttestor{}

	reqA, _, err := newKeyExchangeRequest(attestor)
	require.NoError(t, err)
	reqB, _, err := newKeyExchangeRequest(attestor)
	require.NoError(t, err)

	reqA.Quote = reqB.Quote
	_, err = wrapMasterKey(attestor, reqA, testMasterKey(t))
	require.ErrorContains(t, err, "requester attestation rejected")
}

// The distinct direction labels stop a responder quote being reflected back as
// a requester quote.
func TestKeyExchangeRejectsReflectedResponderQuote(t *testing.T) {
	attestor := fakeAttestor{}

	req, _, err := newKeyExchangeRequest(attestor)
	require.NoError(t, err)
	resp, err := wrapMasterKey(attestor, req, testMasterKey(t))
	require.NoError(t, err)

	reflected := &keyExchangeRequest{
		EphemeralPub: resp.EphemeralPub,
		Nonce:        resp.Nonce,
		Quote:        resp.Quote,
	}
	_, err = wrapMasterKey(attestor, reflected, testMasterKey(t))
	require.ErrorContains(t, err, "requester attestation rejected")
}

// Only the node that started the exchange holds the private half needed to
// derive the wrapping key.
func TestKeyExchangeResponseOnlyUnwrappableByRequester(t *testing.T) {
	// attestation disabled to isolate the ECDH property from the quote check
	attestor := sgx.NewAttestor(nil)

	req, _, err := newKeyExchangeRequest(attestor)
	require.NoError(t, err)
	resp, err := wrapMasterKey(attestor, req, testMasterKey(t))
	require.NoError(t, err)

	_, otherPending, err := newKeyExchangeRequest(attestor)
	require.NoError(t, err)

	_, err = unwrapMasterKey(attestor, otherPending, resp)
	require.ErrorContains(t, err, "unwrapping master key failed")
}

func TestKeyExchangeRejectsTamperedCiphertext(t *testing.T) {
	attestor := fakeAttestor{}

	req, pending, err := newKeyExchangeRequest(attestor)
	require.NoError(t, err)
	resp, err := wrapMasterKey(attestor, req, testMasterKey(t))
	require.NoError(t, err)

	raw, err := base64.StdEncoding.DecodeString(resp.WrappedKey)
	require.NoError(t, err)
	raw[len(raw)-1] ^= 0xff
	resp.WrappedKey = base64.StdEncoding.EncodeToString(raw)

	_, err = unwrapMasterKey(attestor, pending, resp)
	require.ErrorContains(t, err, "unwrapping master key failed")
}

func TestKeyExchangeRejectsMalformedMaterial(t *testing.T) {
	attestor := sgx.NewAttestor(nil)
	secret := testMasterKey(t)

	req, _, err := newKeyExchangeRequest(attestor)
	require.NoError(t, err)

	t.Run("short public key", func(t *testing.T) {
		bad := *req
		bad.EphemeralPub = []byte{1, 2, 3}
		_, err := wrapMasterKey(attestor, &bad, secret)
		require.ErrorContains(t, err, "ephemeral public key length")
	})

	t.Run("short nonce", func(t *testing.T) {
		bad := *req
		bad.Nonce = []byte{1, 2, 3}
		_, err := wrapMasterKey(attestor, &bad, secret)
		require.ErrorContains(t, err, "nonce length")
	})

	t.Run("wrong master key size", func(t *testing.T) {
		_, err := wrapMasterKey(attestor, req, []byte("too short"))
		require.ErrorContains(t, err, "master key length")
	})
}

const testClusterId = "test-cluster"

func TestSeedKeyExchangeRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		attestor sgx.Attestor
	}{
		{"attested", fakeAttestor{}},
		{"attestation disabled", sgx.NewAttestor(nil)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			secret := testMasterKey(t)

			senderOffer, senderKx, err := newSeedOffer(tc.attestor, testClusterId)
			require.NoError(t, err)
			recipientOffer, recipientKx, err := newSeedOffer(tc.attestor, testClusterId)
			require.NoError(t, err)

			// the recipient verifies the offer it received before wrapping to it
			require.NoError(t, verifySeedOffer(tc.attestor, testClusterId, senderOffer))

			init, err := wrapSeedKey(senderKx, senderOffer, recipientOffer, secret)
			require.NoError(t, err)

			raw, err := base64.StdEncoding.DecodeString(init.WrappedKey)
			require.NoError(t, err)
			require.False(t, bytes.Contains(raw, secret), "seed key leaked into the wrapped payload")

			got, err := unwrapSeedKey(tc.attestor, testClusterId, recipientKx, recipientOffer, init)
			require.NoError(t, err)
			require.Equal(t, secret, got)
		})
	}
}

// Both peers of a pair must derive the same transcript regardless of direction.
func TestSeedTranscriptIsOrderIndependent(t *testing.T) {
	a, na, err := newKxEphemeral()
	require.NoError(t, err)
	b, nb, err := newKxEphemeral()
	require.NoError(t, err)

	pubA, pubB := a.PublicKey().Bytes(), b.PublicKey().Bytes()
	require.Equal(t,
		seedTranscript(pubA, na, pubB, nb),
		seedTranscript(pubB, nb, pubA, na),
	)
}

// wk(S->R) must differ from wk(R->S) so a wrap cannot be reflected.
func TestSeedWrapIsDirectionSeparated(t *testing.T) {
	attestor := sgx.NewAttestor(nil)

	aOffer, aKx, err := newSeedOffer(attestor, testClusterId)
	require.NoError(t, err)
	bOffer, _, err := newSeedOffer(attestor, testClusterId)
	require.NoError(t, err)

	secret := testMasterKey(t)
	aToB, err := wrapSeedKey(aKx, aOffer, bOffer, secret)
	require.NoError(t, err)

	// reflect A's ciphertext back at A, relabelled as if B had sent it
	reflected := &seedKeyInit{
		EphemeralPub: bOffer.EphemeralPub,
		Nonce:        bOffer.Nonce,
		Quote:        bOffer.Quote,
		RecipientPub: aOffer.EphemeralPub,
		WrappedKey:   aToB.WrappedKey,
	}
	_, err = unwrapSeedKey(attestor, testClusterId, aKx, aOffer, reflected)
	require.ErrorContains(t, err, "unwrapping seed key failed")
}

// A key wrapped to one peer must not be openable by another.
func TestSeedKeyOnlyUnwrappableByIntendedPeer(t *testing.T) {
	attestor := sgx.NewAttestor(nil)

	senderOffer, senderKx, err := newSeedOffer(attestor, testClusterId)
	require.NoError(t, err)
	recipientOffer, _, err := newSeedOffer(attestor, testClusterId)
	require.NoError(t, err)
	otherOffer, otherKx, err := newSeedOffer(attestor, testClusterId)
	require.NoError(t, err)

	init, err := wrapSeedKey(senderKx, senderOffer, recipientOffer, testMasterKey(t))
	require.NoError(t, err)

	_, err = unwrapSeedKey(attestor, testClusterId, otherKx, otherOffer, init)
	require.ErrorContains(t, err, "not wrapped to this node's offer")
}

// An offer quote is valid only for the cluster it was minted in.
func TestSeedOfferBoundToCluster(t *testing.T) {
	attestor := fakeAttestor{}

	offer, _, err := newSeedOffer(attestor, testClusterId)
	require.NoError(t, err)

	require.NoError(t, verifySeedOffer(attestor, testClusterId, offer))
	require.ErrorContains(t,
		verifySeedOffer(attestor, "other-cluster", offer),
		"seed offer attestation rejected")
}

// Substituting the ephemeral key while forwarding a valid quote must fail.
func TestSeedOfferRejectsSubstitutedKey(t *testing.T) {
	attestor := fakeAttestor{}

	victim, _, err := newSeedOffer(attestor, testClusterId)
	require.NoError(t, err)
	attackerKey, _, err := newKxEphemeral()
	require.NoError(t, err)

	forged := &seedOffer{
		EphemeralPub: attackerKey.PublicKey().Bytes(),
		Nonce:        victim.Nonce,
		Quote:        victim.Quote,
	}
	require.ErrorContains(t,
		verifySeedOffer(attestor, testClusterId, forged),
		"seed offer attestation rejected")
}

func TestSeedKeyRejectsUnattestedSender(t *testing.T) {
	attestor := fakeAttestor{}

	senderOffer, senderKx, err := newSeedOffer(attestor, testClusterId)
	require.NoError(t, err)
	recipientOffer, recipientKx, err := newSeedOffer(attestor, testClusterId)
	require.NoError(t, err)

	init, err := wrapSeedKey(senderKx, senderOffer, recipientOffer, testMasterKey(t))
	require.NoError(t, err)
	init.Quote = nil

	_, err = unwrapSeedKey(attestor, testClusterId, recipientKx, recipientOffer, init)
	require.ErrorContains(t, err, "no quote")
}

// An enabled attestor must never accept a peer that simply omits its quote.
func TestEnabledAttestorRequiresQuote(t *testing.T) {
	attestor := fakeAttestor{}

	req, _, err := newKeyExchangeRequest(attestor)
	require.NoError(t, err)
	req.Quote = nil

	_, err = wrapMasterKey(attestor, req, testMasterKey(t))
	require.ErrorContains(t, err, "no quote")
}
