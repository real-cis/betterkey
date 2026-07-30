// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package web

import (
	"encoding/base64"
	"fmt"

	"gitlab.com/real-cis/cc/betterkey/internal/crypto"
	"gitlab.com/real-cis/cc/betterkey/internal/sgx"
	"gitlab.com/real-cis/cc/betterkey/pkg/aes"
	"gitlab.com/real-cis/cc/betterkey/pkg/api"
)

// Attested key exchange for KDS key delivery.
//
// Derived key material must not be readable by anything between the client TD
// and this enclave. TLS cannot provide that here: the deployment terminates TLS
// at a load balancer, so exporter-based channel binding is impossible and the
// terminator sees the plaintext response. The exchange therefore ignores the
// transport entirely and wraps the key to a key pair the client's TD proved it
// holds - the same construction used for cluster master-key transfer
// (internal/cluster/keyexchange.go), adapted to a TDX client and an SGX server.
//
//	Client (in TD)                          KDS node (SGX)
//	  eph_c generated inside the TD
//	  q_c = TD quote over SHA512(reqLabel|nonce|eph_c.pub)
//	       --- finalize{ sessionId, q_c, eventLog, eph_c.pub } --->
//	                              verify q_c is bound to nonce and eph_c.pub
//	                              eph_s, ss = ECDH(eph_s, eph_c)
//	                              tr = SHA256(eph_c.pub|eph_s.pub|nonce)
//	                              q_s = SGX quote over SHA512(respLabel|tr)
//	                              wk = HKDF(ss, salt=tr, info)
//	       <--- { eph_s.pub, q_s, AESGCM(wk, keyResponseJSON) } ---
//	  verify q_s is bound to tr, then unwrap inside the TD
//
// The client quote binds the session nonce (freshness) and its ephemeral key.
// The server quote binds the whole transcript, so it is valid for exactly one
// exchange and lets the client authenticate the enclave end to end - which the
// TLS layer cannot do once a load balancer terminates it.
const (
	kdsRequestLabel  = "bk-kds-req-v1"
	kdsResponseLabel = "bk-kds-resp-v1"
	kdsWrapInfo      = "betterkey/kds-wrap/v1"
	// kdsKeyExchangeScheme is advertised by /key/init so clients can detect support.
	kdsKeyExchangeScheme = "betterkey/kds-kx/v1"

	// The seal flow wraps in the opposite direction: the client encrypts its
	// payload to an ephemeral key this enclave publishes at init, so the
	// terminator never sees the plaintext on the way in. Distinct labels keep
	// the two directions separate even though the transcript shape is shared.
	sealOfferLabel        = "bk-seal-offer-v1"
	sealRequestLabel      = "bk-seal-req-v1"
	sealWrapInfo          = "betterkey/seal-wrap/v1"
	sealKeyExchangeScheme = "betterkey/seal-kx/v1"

	kdsWrapLen = 32
)

// kdsRequestBinding is the report data the client's TD quote must carry.
func kdsRequestBinding(nonce, clientPub []byte) []byte {
	return crypto.LabeledHash512(kdsRequestLabel, nonce, clientPub)
}

// kdsTranscript binds a wrapping key to one exchange. Both public keys are
// fixed length, so only the trailing nonce may vary.
func kdsTranscript(clientPub, serverPub, nonce []byte) []byte {
	return crypto.Transcript(clientPub, serverPub, nonce)
}

func kdsResponseBinding(transcript []byte) []byte {
	return crypto.LabeledHash512(kdsResponseLabel, transcript)
}

func validateEphemeralPub(pub []byte) error {
	return crypto.ValidatePublicKey(pub)
}

// sealOfferBinding is the report data of the quote published at seal init: it
// commits this enclave to the ephemeral key the client will wrap its payload to.
func sealOfferBinding(nonce, serverPub []byte) []byte {
	return crypto.LabeledHash512(sealOfferLabel, nonce, serverPub)
}

// sealRequestBinding is the report data the client's TD quote must carry when
// submitting a wrapped seal payload.
func sealRequestBinding(nonce, clientPub []byte) []byte {
	return crypto.LabeledHash512(sealRequestLabel, nonce, clientPub)
}

// newSealOffer generates this node's ephemeral key for a seal session and
// quotes it, so the client can confirm it is wrapping to a genuine enclave.
// The private key is returned for storage in the session record: init and
// finalize may be served by different nodes.
func newSealOffer(attestor sgx.Attestor, nonce []byte) (priv []byte, pub []byte, quote []byte, err error) {
	key, err := crypto.NewEphemeral()
	if err != nil {
		return nil, nil, nil, err
	}
	pub = key.Public()
	quote, err = attestor.Quote(sealOfferBinding(nonce, pub))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("quoting ephemeral key failed: %w", err)
	}
	return key.PrivateBytes(), pub, quote, nil
}

// unwrapSealPayload opens a payload the client encrypted to this node's offer.
func unwrapSealPayload(serverPriv, clientPub, nonce []byte, wrapped string) ([]byte, error) {
	if err := validateEphemeralPub(clientPub); err != nil {
		return nil, err
	}
	key, err := crypto.EphemeralFromBytes(serverPriv)
	if err != nil {
		return nil, err
	}
	shared, err := key.SharedSecret(clientPub)
	if err != nil {
		return nil, err
	}
	transcript := kdsTranscript(clientPub, key.Public(), nonce)
	wrappingKey, err := crypto.HKDF(shared, transcript, []byte(sealWrapInfo), kdsWrapLen)
	if err != nil {
		return nil, err
	}
	payload, err := aes.DecryptAESGCM(wrappingKey, wrapped)
	if err != nil {
		return nil, fmt.Errorf("unwrapping seal payload failed: %w", err)
	}
	return payload, nil
}

// wrapKeyResponse encrypts payload to the client's attested ephemeral key. Only
// the TD that proved possession of clientPub can open it, so the derived key
// stays confidential across any TLS terminator in the path.
func wrapKeyResponse(attestor sgx.Attestor, clientPub, nonce, payload []byte) (*api.WrappedKeyResponse, error) {
	if err := validateEphemeralPub(clientPub); err != nil {
		return nil, err
	}
	key, err := crypto.NewEphemeral()
	if err != nil {
		return nil, err
	}
	shared, err := key.SharedSecret(clientPub)
	if err != nil {
		return nil, err
	}

	serverPub := key.Public()
	transcript := kdsTranscript(clientPub, serverPub, nonce)
	quote, err := attestor.Quote(kdsResponseBinding(transcript))
	if err != nil {
		return nil, fmt.Errorf("quoting ephemeral key failed: %w", err)
	}
	wrappingKey, err := crypto.HKDF(shared, transcript, []byte(kdsWrapInfo), kdsWrapLen)
	if err != nil {
		return nil, err
	}
	wrapped, err := aes.EncryptAESGCM(wrappingKey, payload)
	if err != nil {
		return nil, fmt.Errorf("wrapping key response failed: %w", err)
	}

	resp := &api.WrappedKeyResponse{
		EphemeralPub: serverPub,
		WrappedKey:   wrapped,
		Verified:     true,
	}
	if len(quote) > 0 {
		resp.Quote = base64.StdEncoding.EncodeToString(quote)
	}
	return resp, nil
}
