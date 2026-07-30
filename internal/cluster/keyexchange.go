// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package cluster

import (
	"bytes"
	"errors"
	"fmt"

	"gitlab.com/real-cis/cc/betterkey/internal/crypto"
	"gitlab.com/real-cis/cc/betterkey/internal/sgx"
	"gitlab.com/real-cis/cc/betterkey/pkg/aes"
)

// Attested ephemeral key exchange for master-key transfer.
//
// The master key is never put on the wire in plaintext, not even inside the
// attested TLS channel. Both sides contribute an ephemeral X25519 key generated
// inside their enclave and quote it; the responder then encrypts the master key
// to the ECDH shared secret. An attacker who relays or intercepts the RA-TLS
// session therefore obtains ciphertext only, because the wrapping key exists
// solely inside the two enclaves that proved possession of the ephemeral keys.
//
//	Requester                                    Responder
//	  eph_r, n_r
//	  q_r = quote(SHA512(reqLabel|eph_r|n_r))
//	       --- KEYQUERY{eph_r, n_r, q_r} --->
//	                                      verify q_r is bound to eph_r, n_r
//	                                      eph_s, n_s; ss = ECDH(eph_s, eph_r)
//	                                      tr = SHA256(eph_r|eph_s|n_r|n_s)
//	                                      q_s = quote(SHA512(respLabel|tr))
//	                                      wk = HKDF(ss, salt=tr, info)
//	       <-- KEYQUERY_RESP{eph_s, n_s, q_s, AESGCM(wk, mk)} ---
//	  verify q_s is bound to tr; unwrap
//
// The two labels are distinct so a quote minted for one direction cannot be
// reflected back as the other. The response binding covers the full transcript
// (both keys, both nonces), so a quote is valid for exactly one exchange.
const (
	kxRequestLabel  = "bk-kx-req-v1"
	kxResponseLabel = "bk-kx-resp-v1"
	kxWrapInfo      = "betterkey/mk-wrap/v1"

	// Seeding uses the same primitives with its own labels. Seeding is a push:
	// a sender must wrap before hearing anything from the recipient, so each
	// node first publishes one attested ephemeral key (its "offer") that every
	// other seed node wraps to. One quote per node per round rather than one
	// per pair.
	kxSeedOfferLabel = "bk-seed-offer-v1"
	kxSeedWrapInfo   = "betterkey/seed-wrap/v1"

	kxNonceLen   = 32
	masterKeyLen = 32
)

// keyExchangeRequest is the payload of MSG_TYPE_KEYQUERY.
type keyExchangeRequest struct {
	EphemeralPub []byte `json:"ephemeralPub"`
	Nonce        []byte `json:"nonce"`
	Quote        []byte `json:"quote,omitempty"`
}

// keyExchangeResponse is the payload of MSG_TYPE_KEYQUERY_RESP.
type keyExchangeResponse struct {
	EphemeralPub []byte `json:"ephemeralPub"`
	Nonce        []byte `json:"nonce"`
	Quote        []byte `json:"quote,omitempty"`
	WrappedKey   string `json:"wrappedKey"`
}

// pendingKeyExchange is the requester's state between sending a key query and
// receiving the response. The private key never leaves the enclave.
type pendingKeyExchange struct {
	priv  *crypto.Ephemeral
	nonce []byte
}

func kxRequestBinding(ephPub, nonce []byte) []byte {
	return crypto.LabeledHash512(kxRequestLabel, ephPub, nonce)
}

// kxTranscript covers both keys and both nonces; all four are fixed length, so
// the concatenation is unambiguous.
func kxTranscript(reqPub, respPub, reqNonce, respNonce []byte) []byte {
	return crypto.Transcript(reqPub, respPub, reqNonce, respNonce)
}

func kxResponseBinding(transcript []byte) []byte {
	return crypto.LabeledHash512(kxResponseLabel, transcript)
}

func kxWrappingKey(shared, transcript []byte) ([]byte, error) {
	return crypto.HKDF(shared, transcript, []byte(kxWrapInfo), masterKeyLen)
}

func validateKxPeerMaterial(pub, nonce []byte) error {
	if err := crypto.ValidatePublicKey(pub); err != nil {
		return err
	}
	if len(nonce) != kxNonceLen {
		return fmt.Errorf("bad nonce length %d, want %d", len(nonce), kxNonceLen)
	}
	return nil
}

func newKxEphemeral() (*crypto.Ephemeral, []byte, error) {
	priv, err := crypto.NewEphemeral()
	if err != nil {
		return nil, nil, err
	}
	return priv, crypto.GenerateNonce(kxNonceLen), nil
}

// newKeyExchangeRequest generates the requester's ephemeral key pair and quotes
// it. The returned pendingKeyExchange must be retained to unwrap the response.
func newKeyExchangeRequest(attestor sgx.Attestor) (*keyExchangeRequest, *pendingKeyExchange, error) {
	priv, nonce, err := newKxEphemeral()
	if err != nil {
		return nil, nil, err
	}
	pub := priv.Public()
	quote, err := attestor.Quote(kxRequestBinding(pub, nonce))
	if err != nil {
		return nil, nil, fmt.Errorf("quoting ephemeral key failed: %w", err)
	}
	req := &keyExchangeRequest{EphemeralPub: pub, Nonce: nonce, Quote: quote}
	return req, &pendingKeyExchange{priv: priv, nonce: nonce}, nil
}

// wrapMasterKey verifies that the requester's quote is bound to the ephemeral
// key it sent, then encrypts secret to the ECDH shared secret.
func wrapMasterKey(attestor sgx.Attestor, req *keyExchangeRequest, secret []byte) (*keyExchangeResponse, error) {
	if err := validateKxPeerMaterial(req.EphemeralPub, req.Nonce); err != nil {
		return nil, err
	}
	if len(secret) != masterKeyLen {
		return nil, fmt.Errorf("bad master key length %d, want %d", len(secret), masterKeyLen)
	}
	// Bound to the ephemeral key just received, so a replayed or relayed quote
	// cannot be paired with a key the peer's enclave never vouched for.
	if err := attestor.VerifyQuote(req.Quote, kxRequestBinding(req.EphemeralPub, req.Nonce)); err != nil {
		return nil, fmt.Errorf("requester attestation rejected: %w", err)
	}

	priv, nonce, err := newKxEphemeral()
	if err != nil {
		return nil, err
	}
	shared, err := priv.SharedSecret(req.EphemeralPub)
	if err != nil {
		return nil, err
	}

	pub := priv.Public()
	transcript := kxTranscript(req.EphemeralPub, pub, req.Nonce, nonce)
	quote, err := attestor.Quote(kxResponseBinding(transcript))
	if err != nil {
		return nil, fmt.Errorf("quoting ephemeral key failed: %w", err)
	}
	wrappingKey, err := kxWrappingKey(shared, transcript)
	if err != nil {
		return nil, err
	}
	wrapped, err := aes.EncryptAESGCM(wrappingKey, secret)
	if err != nil {
		return nil, fmt.Errorf("wrapping master key failed: %w", err)
	}

	return &keyExchangeResponse{
		EphemeralPub: pub,
		Nonce:        nonce,
		Quote:        quote,
		WrappedKey:   wrapped,
	}, nil
}

// seedOffer is the payload of MSG_TYPE_SEED_OFFER: a node's attested ephemeral
// public key for one seeding round.
type seedOffer struct {
	EphemeralPub []byte `json:"ephemeralPub"`
	Nonce        []byte `json:"nonce"`
	Quote        []byte `json:"quote,omitempty"`
}

// seedKeyInit is the payload of MSG_TYPE_KEYINIT. The sender's own offer is
// carried inline so the message is self-contained: a recipient that never saw
// the sender's broadcast offer can still verify and unwrap it.
type seedKeyInit struct {
	EphemeralPub []byte `json:"ephemeralPub"`
	Nonce        []byte `json:"nonce"`
	Quote        []byte `json:"quote,omitempty"`
	// RecipientPub identifies which offer the key was wrapped to.
	RecipientPub []byte `json:"recipientPub"`
	WrappedKey   string `json:"wrappedKey"`
}

// seedOfferBinding includes the cluster id so an offer cannot be replayed into
// a different cluster. The trailing fields are fixed length, so the
// concatenation stays unambiguous despite the variable-length id.
func seedOfferBinding(clusterId string, ephPub, nonce []byte) []byte {
	return crypto.LabeledHash512(kxSeedOfferLabel, []byte(clusterId), ephPub, nonce)
}

// seedTranscript is order independent: both peers of a pair derive the same
// value regardless of which of them is sending.
func seedTranscript(pubA, nonceA, pubB, nonceB []byte) []byte {
	loPub, loNonce, hiPub, hiNonce := pubA, nonceA, pubB, nonceB
	if bytes.Compare(pubA, pubB) > 0 {
		loPub, loNonce, hiPub, hiNonce = pubB, nonceB, pubA, nonceA
	}
	return crypto.Transcript(loPub, hiPub, loNonce, hiNonce)
}

// seedWrappingKey derives a direction-separated key. Including the sender's
// ephemeral public key in the info means wk(S->R) != wk(R->S), so a wrapped key
// cannot be reflected back at its sender.
func seedWrappingKey(shared, transcript, senderPub []byte) ([]byte, error) {
	info := append([]byte(kxSeedWrapInfo), senderPub...)
	return crypto.HKDF(shared, transcript, info, masterKeyLen)
}

// newSeedOffer generates and quotes this node's ephemeral key for a seeding
// round. The returned pendingKeyExchange must be retained for the whole round.
func newSeedOffer(attestor sgx.Attestor, clusterId string) (*seedOffer, *pendingKeyExchange, error) {
	priv, nonce, err := newKxEphemeral()
	if err != nil {
		return nil, nil, err
	}
	pub := priv.Public()
	quote, err := attestor.Quote(seedOfferBinding(clusterId, pub, nonce))
	if err != nil {
		return nil, nil, fmt.Errorf("quoting seed offer failed: %w", err)
	}
	return &seedOffer{EphemeralPub: pub, Nonce: nonce, Quote: quote},
		&pendingKeyExchange{priv: priv, nonce: nonce}, nil
}

func verifySeedOffer(attestor sgx.Attestor, clusterId string, offer *seedOffer) error {
	if err := validateKxPeerMaterial(offer.EphemeralPub, offer.Nonce); err != nil {
		return err
	}
	if err := attestor.VerifyQuote(offer.Quote,
		seedOfferBinding(clusterId, offer.EphemeralPub, offer.Nonce)); err != nil {
		return fmt.Errorf("seed offer attestation rejected: %w", err)
	}
	return nil
}

// wrapSeedKey encrypts secret to a peer's already-verified offer. Only the
// enclave that proved possession of that offer's private half can open it.
func wrapSeedKey(selfKx *pendingKeyExchange, selfOffer, peer *seedOffer, secret []byte) (*seedKeyInit, error) {
	if len(secret) != masterKeyLen {
		return nil, fmt.Errorf("bad master key length %d, want %d", len(secret), masterKeyLen)
	}
	shared, err := selfKx.priv.SharedSecret(peer.EphemeralPub)
	if err != nil {
		return nil, err
	}
	transcript := seedTranscript(selfOffer.EphemeralPub, selfOffer.Nonce, peer.EphemeralPub, peer.Nonce)
	wrappingKey, err := seedWrappingKey(shared, transcript, selfOffer.EphemeralPub)
	if err != nil {
		return nil, err
	}
	wrapped, err := aes.EncryptAESGCM(wrappingKey, secret)
	if err != nil {
		return nil, fmt.Errorf("wrapping seed key failed: %w", err)
	}
	return &seedKeyInit{
		EphemeralPub: selfOffer.EphemeralPub,
		Nonce:        selfOffer.Nonce,
		Quote:        selfOffer.Quote,
		RecipientPub: peer.EphemeralPub,
		WrappedKey:   wrapped,
	}, nil
}

// unwrapSeedKey verifies the sender's inline offer and decrypts the seed key.
func unwrapSeedKey(attestor sgx.Attestor, clusterId string, selfKx *pendingKeyExchange,
	selfOffer *seedOffer, init *seedKeyInit) ([]byte, error) {
	sender := &seedOffer{EphemeralPub: init.EphemeralPub, Nonce: init.Nonce, Quote: init.Quote}
	if err := verifySeedOffer(attestor, clusterId, sender); err != nil {
		return nil, err
	}
	if !bytes.Equal(init.RecipientPub, selfOffer.EphemeralPub) {
		return nil, errors.New("seed key was not wrapped to this node's offer")
	}
	shared, err := selfKx.priv.SharedSecret(init.EphemeralPub)
	if err != nil {
		return nil, err
	}
	transcript := seedTranscript(selfOffer.EphemeralPub, selfOffer.Nonce, init.EphemeralPub, init.Nonce)
	wrappingKey, err := seedWrappingKey(shared, transcript, init.EphemeralPub)
	if err != nil {
		return nil, err
	}
	secret, err := aes.DecryptAESGCM(wrappingKey, init.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("unwrapping seed key failed: %w", err)
	}
	if len(secret) != masterKeyLen {
		return nil, fmt.Errorf("unexpected seed key length %d, want %d", len(secret), masterKeyLen)
	}
	return secret, nil
}

// unwrapMasterKey verifies that the responder's quote is bound to this exchange
// and decrypts the master key with the ECDH-derived wrapping key.
func unwrapMasterKey(attestor sgx.Attestor, pending *pendingKeyExchange, resp *keyExchangeResponse) ([]byte, error) {
	if err := validateKxPeerMaterial(resp.EphemeralPub, resp.Nonce); err != nil {
		return nil, err
	}
	ownPub := pending.priv.Public()
	transcript := kxTranscript(ownPub, resp.EphemeralPub, pending.nonce, resp.Nonce)
	if err := attestor.VerifyQuote(resp.Quote, kxResponseBinding(transcript)); err != nil {
		return nil, fmt.Errorf("responder attestation rejected: %w", err)
	}

	shared, err := pending.priv.SharedSecret(resp.EphemeralPub)
	if err != nil {
		return nil, err
	}
	wrappingKey, err := kxWrappingKey(shared, transcript)
	if err != nil {
		return nil, err
	}
	secret, err := aes.DecryptAESGCM(wrappingKey, resp.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("unwrapping master key failed: %w", err)
	}
	if len(secret) != masterKeyLen {
		return nil, fmt.Errorf("unexpected master key length %d, want %d", len(secret), masterKeyLen)
	}
	return secret, nil
}
