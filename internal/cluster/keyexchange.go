// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package cluster

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
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

	kxNonceLen = 32
	// X25519 public keys are always 32 bytes; fixed lengths keep the hashed
	// concatenations in the bindings unambiguous.
	kxPubLen     = 32
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
	priv  *ecdh.PrivateKey
	nonce []byte
}

func kxRequestBinding(ephPub, nonce []byte) []byte {
	h := sha512.New()
	h.Write([]byte(kxRequestLabel))
	h.Write(ephPub)
	h.Write(nonce)
	return h.Sum(nil)
}

func kxTranscript(reqPub, respPub, reqNonce, respNonce []byte) []byte {
	h := sha256.New()
	h.Write(reqPub)
	h.Write(respPub)
	h.Write(reqNonce)
	h.Write(respNonce)
	return h.Sum(nil)
}

func kxResponseBinding(transcript []byte) []byte {
	h := sha512.New()
	h.Write([]byte(kxResponseLabel))
	h.Write(transcript)
	return h.Sum(nil)
}

func kxWrappingKey(shared, transcript []byte) ([]byte, error) {
	return crypto.HKDF(shared, transcript, []byte(kxWrapInfo), masterKeyLen)
}

func validateKxPeerMaterial(pub, nonce []byte) error {
	if len(pub) != kxPubLen {
		return fmt.Errorf("bad ephemeral public key length %d, want %d", len(pub), kxPubLen)
	}
	if len(nonce) != kxNonceLen {
		return fmt.Errorf("bad nonce length %d, want %d", len(nonce), kxNonceLen)
	}
	return nil
}

func newKxEphemeral() (*ecdh.PrivateKey, []byte, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating ephemeral key failed: %w", err)
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
	pub := priv.PublicKey().Bytes()
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

	peerPub, err := ecdh.X25519().NewPublicKey(req.EphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("bad ephemeral public key: %w", err)
	}
	priv, nonce, err := newKxEphemeral()
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh failed: %w", err)
	}

	pub := priv.PublicKey().Bytes()
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

// unwrapMasterKey verifies that the responder's quote is bound to this exchange
// and decrypts the master key with the ECDH-derived wrapping key.
func unwrapMasterKey(attestor sgx.Attestor, pending *pendingKeyExchange, resp *keyExchangeResponse) ([]byte, error) {
	if err := validateKxPeerMaterial(resp.EphemeralPub, resp.Nonce); err != nil {
		return nil, err
	}
	ownPub := pending.priv.PublicKey().Bytes()
	transcript := kxTranscript(ownPub, resp.EphemeralPub, pending.nonce, resp.Nonce)
	if err := attestor.VerifyQuote(resp.Quote, kxResponseBinding(transcript)); err != nil {
		return nil, fmt.Errorf("responder attestation rejected: %w", err)
	}

	peerPub, err := ecdh.X25519().NewPublicKey(resp.EphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("bad ephemeral public key: %w", err)
	}
	shared, err := pending.priv.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh failed: %w", err)
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
