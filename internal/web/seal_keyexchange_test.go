// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package web

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/real-cis/cc/betterkey/internal/crypto"
	"gitlab.com/real-cis/cc/betterkey/internal/sgx"
	"gitlab.com/real-cis/cc/betterkey/pkg/aes"
)

// sealClient performs the client half of the seal exchange: it wraps its
// payload to the ephemeral key the enclave published at init.
type sealClient struct {
	priv *ecdh.PrivateKey
	pub  []byte
}

func newSealClient(t *testing.T) *sealClient {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return &sealClient{priv: priv, pub: priv.PublicKey().Bytes()}
}

func (c *sealClient) wrap(t *testing.T, serverPub, nonce, payload []byte) string {
	t.Helper()
	peer, err := ecdh.X25519().NewPublicKey(serverPub)
	require.NoError(t, err)
	shared, err := c.priv.ECDH(peer)
	require.NoError(t, err)
	transcript := kdsTranscript(c.pub, serverPub, nonce)
	wk, err := crypto.HKDF(shared, transcript, []byte(sealWrapInfo), kdsWrapLen)
	require.NoError(t, err)
	wrapped, err := aes.EncryptAESGCM(wk, payload)
	require.NoError(t, err)
	return wrapped
}

func TestSealPayloadRoundTrip(t *testing.T) {
	attestor := sgx.NewAttestor(nil)
	nonce := crypto.GenerateNonce(64)
	secret := []byte("the-plaintext-payload-to-seal")

	priv, pub, _, err := newSealOffer(attestor, nonce)
	require.NoError(t, err)
	require.Len(t, pub, crypto.PublicKeyLen)

	client := newSealClient(t)
	wrapped := client.wrap(t, pub, nonce, secret)

	// the payload must not be readable on the wire
	raw, err := base64.StdEncoding.DecodeString(wrapped)
	require.NoError(t, err)
	require.False(t, bytes.Contains(raw, secret), "payload leaked into the wrapped request")

	got, err := unwrapSealPayload(priv, client.pub, nonce, wrapped)
	require.NoError(t, err)
	require.Equal(t, secret, got)
}

// The point of the change: the TLS terminator sees the request but cannot read
// the payload, because it does not hold the enclave's ephemeral private key.
func TestSealPayloadUnreadableWithoutEnclaveKey(t *testing.T) {
	attestor := sgx.NewAttestor(nil)
	nonce := crypto.GenerateNonce(64)

	_, pub, _, err := newSealOffer(attestor, nonce)
	require.NoError(t, err)

	client := newSealClient(t)
	wrapped := client.wrap(t, pub, nonce, []byte("secret"))

	// an observer generates its own key pair and holds the full request
	other, _, _, err := newSealOffer(attestor, nonce)
	require.NoError(t, err)
	_, err = unwrapSealPayload(other, client.pub, nonce, wrapped)
	require.ErrorContains(t, err, "unwrapping seal payload failed")
}

// A payload wrapped for one session must not open in another.
func TestSealPayloadBoundToSession(t *testing.T) {
	attestor := sgx.NewAttestor(nil)
	nonce := crypto.GenerateNonce(64)
	otherNonce := crypto.GenerateNonce(64)

	priv, pub, _, err := newSealOffer(attestor, nonce)
	require.NoError(t, err)

	client := newSealClient(t)
	wrapped := client.wrap(t, pub, nonce, []byte("secret"))

	_, err = unwrapSealPayload(priv, client.pub, otherNonce, wrapped)
	require.ErrorContains(t, err, "unwrapping seal payload failed")
}

// The offer quote commits the enclave to the key the client wraps to, so a
// substituted key cannot be passed off as the enclave's.
func TestSealOfferQuoteBindsEphemeralKey(t *testing.T) {
	attestor := fakeKdsAttestor{}
	nonce := crypto.GenerateNonce(64)

	_, pub, quote, err := newSealOffer(attestor, nonce)
	require.NoError(t, err)
	require.Equal(t, sealOfferBinding(nonce, pub), quote)

	attacker := newSealClient(t)
	require.NotEqual(t, sealOfferBinding(nonce, attacker.pub), quote,
		"a substituted ephemeral key must not match the offer quote")
	require.NotEqual(t, sealOfferBinding(crypto.GenerateNonce(64), pub), quote,
		"the session nonce must be bound in")
}

// Seal and key-delivery wrapping must not be interchangeable, even though both
// derive from the same transcript shape.
func TestSealAndKdsWrappingAreDomainSeparated(t *testing.T) {
	nonce := crypto.GenerateNonce(64)
	client := newSealClient(t)
	server := newSealClient(t)

	shared, err := client.priv.ECDH(server.priv.PublicKey())
	require.NoError(t, err)
	transcript := kdsTranscript(client.pub, server.pub, nonce)

	sealKey, err := crypto.HKDF(shared, transcript, []byte(sealWrapInfo), kdsWrapLen)
	require.NoError(t, err)
	kdsKey, err := crypto.HKDF(shared, transcript, []byte(kdsWrapInfo), kdsWrapLen)
	require.NoError(t, err)
	require.NotEqual(t, sealKey, kdsKey)

	require.NotEqual(t, sealRequestBinding(nonce, client.pub), kdsRequestBinding(nonce, client.pub),
		"request bindings must differ between the seal and key flows")
	require.NotEqual(t, sealOfferBinding(nonce, server.pub), sealRequestBinding(nonce, server.pub),
		"offer and request bindings must differ")
}

// A client that opens the wrapped flow but sends nothing must be rejected
// rather than sealing an empty payload.
func TestSealRejectsMissingWrappedPayload(t *testing.T) {
	attestor := sgx.NewAttestor(nil)
	nonce := crypto.GenerateNonce(64)

	priv, _, _, err := newSealOffer(attestor, nonce)
	require.NoError(t, err)
	client := newSealClient(t)

	_, err = unwrapSealPayload(priv, client.pub, nonce, "")
	require.Error(t, err)
}

func TestSealRejectsMalformedClientKey(t *testing.T) {
	attestor := sgx.NewAttestor(nil)
	nonce := crypto.GenerateNonce(64)

	priv, _, _, err := newSealOffer(attestor, nonce)
	require.NoError(t, err)

	_, err = unwrapSealPayload(priv, []byte{1, 2, 3}, nonce, "irrelevant")
	require.ErrorContains(t, err, "ephemeral public key length")
}
