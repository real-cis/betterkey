// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package web

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/real-cis/cc/betterkey/internal/crypto"
	"gitlab.com/real-cis/cc/betterkey/internal/sgx"
	"gitlab.com/real-cis/cc/betterkey/pkg/aes"
	"gitlab.com/real-cis/cc/betterkey/pkg/api"
)

// testClient stands in for the client TD: it holds the ephemeral private key
// and performs the unwrap the TD would do.
type testClient struct {
	priv  *ecdh.PrivateKey
	pub   []byte
	nonce []byte
}

func newTestClient(t *testing.T) *testClient {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return &testClient{priv: priv, pub: priv.PublicKey().Bytes(), nonce: crypto.GenerateNonce(64)}
}

// reportData is what the client's TD quote must carry.
func (c *testClient) reportData() []byte {
	return kdsRequestBinding(c.nonce, c.pub)
}

func (c *testClient) unwrap(t *testing.T, resp *api.WrappedKeyResponse) ([]byte, error) {
	t.Helper()
	serverPub, err := ecdh.X25519().NewPublicKey(resp.EphemeralPub)
	if err != nil {
		return nil, err
	}
	shared, err := c.priv.ECDH(serverPub)
	if err != nil {
		return nil, err
	}
	transcript := kdsTranscript(c.pub, resp.EphemeralPub, c.nonce)
	wk, err := crypto.HKDF(shared, transcript, []byte(kdsWrapInfo), kdsWrapLen)
	if err != nil {
		return nil, err
	}
	return aes.DecryptAESGCM(wk, resp.WrappedKey)
}

func TestKdsKeyExchangeRoundTrip(t *testing.T) {
	attestor := sgx.NewAttestor(nil)
	client := newTestClient(t)
	payload, err := json.Marshal(api.KeyResponse{Key: "s3cret-derived-key", Verified: true})
	require.NoError(t, err)

	// the client's TD quote carries this; the server recomputes it to verify
	require.Equal(t, kdsRequestBinding(client.nonce, client.pub), client.reportData())

	resp, err := wrapKeyResponse(attestor, client.pub, client.nonce, payload)
	require.NoError(t, err)
	require.Len(t, resp.EphemeralPub, crypto.PublicKeyLen)

	// the derived key must not appear on the wire
	raw, err := base64.StdEncoding.DecodeString(resp.WrappedKey)
	require.NoError(t, err)
	require.False(t, bytes.Contains(raw, []byte("s3cret-derived-key")),
		"key material leaked into the wrapped payload")

	got, err := client.unwrap(t, resp)
	require.NoError(t, err)

	var decoded api.KeyResponse
	require.NoError(t, json.Unmarshal(got, &decoded))
	require.Equal(t, "s3cret-derived-key", decoded.Key)
}

// The whole point: anyone in the path who is not the attesting TD - notably the
// TLS-terminating load balancer - cannot open the response.
func TestKdsKeyExchangeOnlyUnwrappableByAttestingClient(t *testing.T) {
	attestor := sgx.NewAttestor(nil)
	client := newTestClient(t)
	interceptor := newTestClient(t)

	payload := []byte(`{"key":"derived"}`)
	resp, err := wrapKeyResponse(attestor, client.pub, client.nonce, payload)
	require.NoError(t, err)

	// an observer with its own key pair holds the ciphertext and both public
	// keys, and still cannot derive the wrapping key
	_, err = interceptor.unwrap(t, resp)
	require.Error(t, err)
}

// The server quote must be bound to this exchange, so a client can tell it is
// talking to a genuine enclave end to end rather than to the terminator.
func TestKdsServerQuoteBoundToTranscript(t *testing.T) {
	attestor := fakeKdsAttestor{}
	client := newTestClient(t)

	resp, err := wrapKeyResponse(attestor, client.pub, client.nonce, []byte(`{"key":"derived"}`))
	require.NoError(t, err)
	require.NotEmpty(t, resp.Quote)

	quote, err := base64.StdEncoding.DecodeString(resp.Quote)
	require.NoError(t, err)

	transcript := kdsTranscript(client.pub, resp.EphemeralPub, client.nonce)
	require.Equal(t, kdsResponseBinding(transcript), quote,
		"server quote must be bound to the exchange transcript")

	// a transcript from a different exchange must not match
	other := newTestClient(t)
	otherTranscript := kdsTranscript(other.pub, resp.EphemeralPub, other.nonce)
	require.NotEqual(t, kdsResponseBinding(otherTranscript), quote)
}

var errQuoteUnbound = errors.New("quote is not bound to this exchange")

// fakeKdsAttestor returns the report data as the quote, so verification reduces
// to the binding check.
type fakeKdsAttestor struct{}

func (fakeKdsAttestor) Enabled() bool                   { return true }
func (fakeKdsAttestor) Quote(rd []byte) ([]byte, error) { return bytes.Clone(rd), nil }
func (fakeKdsAttestor) VerifyQuote(quote, expected []byte) error {
	if !bytes.Equal(quote, expected) {
		return errQuoteUnbound
	}
	return nil
}

// The client quote is bound to its ephemeral key, so a relay cannot forward a
// genuine quote alongside a key pair it controls.
func TestKdsRequestBindingCoversEphemeralKey(t *testing.T) {
	client := newTestClient(t)
	attacker := newTestClient(t)

	base := kdsRequestBinding(client.nonce, client.pub)
	require.Len(t, base, sha512.Size)

	require.NotEqual(t, base, kdsRequestBinding(client.nonce, attacker.pub),
		"swapping the ephemeral key must change the binding")
	require.NotEqual(t, base, kdsRequestBinding(attacker.nonce, client.pub),
		"the session nonce must be bound in")
	require.Equal(t, base, kdsRequestBinding(client.nonce, client.pub),
		"derivation must be deterministic")
}

func TestResolveKeyExchange(t *testing.T) {
	client := newTestClient(t)
	nonce := client.nonce

	t.Run("ephemeral key present selects the wrapped flow", func(t *testing.T) {
		s := &KeyServer{}
		expected, wrap, e := s.resolveKeyExchange(api.AttestationRequest{EphemeralPub: client.pub}, nonce)
		require.Nil(t, e)
		require.True(t, wrap)
		require.Equal(t, kdsRequestBinding(nonce, client.pub), expected)
	})

	t.Run("legacy request allowed while migrating", func(t *testing.T) {
		s := &KeyServer{}
		expected, wrap, e := s.resolveKeyExchange(api.AttestationRequest{}, nonce)
		require.Nil(t, e)
		require.False(t, wrap)
		require.Equal(t, nonce, expected, "legacy quotes are over the bare nonce")
	})

	t.Run("legacy request refused once enforced", func(t *testing.T) {
		s := &KeyServer{enforceKeyWrapping: true}
		_, _, e := s.resolveKeyExchange(api.AttestationRequest{}, nonce)
		require.NotNil(t, e)
		require.Equal(t, http.StatusBadRequest, e.Code)
	})

	t.Run("malformed ephemeral key rejected", func(t *testing.T) {
		s := &KeyServer{}
		_, _, e := s.resolveKeyExchange(api.AttestationRequest{EphemeralPub: []byte{1, 2, 3}}, nonce)
		require.NotNil(t, e)
		require.Equal(t, http.StatusBadRequest, e.Code)
	})
}
