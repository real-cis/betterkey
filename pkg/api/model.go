// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package api

type VerifyResponse struct {
	Nonce     string `json:"nonce"`
	SessionId string `json:"sessionId"`
	// KeyExchange names the attested key-exchange scheme the client should use
	// to receive key material; empty means none is offered.
	KeyExchange string `json:"keyExchange,omitempty"`
	// KeyExchangeRequired reports whether requests without an ephemeral key are
	// rejected. Clients that cannot participate must fail closed when set.
	KeyExchangeRequired bool `json:"keyExchangeRequired,omitempty"`
	// EphemeralPub is this node's X25519 public key for the session, published
	// when the flow accepts a request payload wrapped to the enclave.
	EphemeralPub []byte `json:"ephemeralPub,omitempty"`
	// Quote is the server's SGX quote binding Nonce and EphemeralPub, base64.
	// It lets the client confirm it is wrapping to a genuine enclave.
	Quote string `json:"quote,omitempty"`
}

type AttestationRequest struct {
	SessionId string `json:"sessionId"`
	Quote     string `json:"quote"`
	EventLog  string `json:"eventLog,omitempty"`
	// EphemeralPub is the client's X25519 public key (32 bytes), generated
	// inside the TD. When present, the quote's report data must be bound to it
	// and the key material is returned wrapped to it.
	EphemeralPub []byte `json:"ephemeralPub,omitempty"`
	// WrappedPayload is base64 AES-GCM of a seal payload, encrypted to the
	// server's ephemeral key published at init. Seal flow only.
	WrappedPayload string `json:"wrappedPayload,omitempty"`
}

// WrappedKeyResponse carries key material encrypted to the client's attested
// ephemeral key, so it stays confidential across any TLS terminator.
type WrappedKeyResponse struct {
	// EphemeralPub is the server's X25519 public key for this exchange.
	EphemeralPub []byte `json:"ephemeralPub"`
	// Quote is the server's SGX quote over the exchange transcript, base64.
	Quote string `json:"quote,omitempty"`
	// WrappedKey is base64 AES-GCM (12-byte nonce || ciphertext) of a
	// KeyResponse JSON document.
	WrappedKey string `json:"wrappedKey"`
	Verified   bool   `json:"verified"`
}

type AttestationRequestStore struct {
	Nonce   []byte `json:"nonce"`
	Payload string `json:"payload"`
	// ServerEphemeralPriv is the X25519 private key this node published at
	// init, needed to open a wrapped request payload at finalize. It lives only
	// in the session store - which is encrypted with the cluster master key -
	// because init and finalize may be served by different nodes.
	ServerEphemeralPriv []byte `json:"serverEphemeralPriv,omitempty"`
}

type KeyType string

const (
	Symmetric KeyType = "SYMMETRIC"
	X25519    KeyType = "X25519"
	P256      KeyType = "P256"
	P384      KeyType = "P384"
	RSA       KeyType = "RSA"
)

type Context string

const (
	ContextApp    Context = "APP"
	ContextVMBoot Context = "VM_BOOT"
)

type KeyRequest struct {
	Id   string  `json:"id"`
	Ctx  Context `json:"context"`
	Type KeyType `json:"type"`
}

type KeyResponse struct {
	Key      any    `json:"key"`
	Verified bool   `json:"verified"`
	Message  string `json:"message"`
}

type SGXQuote struct {
	//base64
	SignedQuote string `json:"signedQuote"`
}

type SigningRequest struct {
	Id       string            `json:"id"`
	Ctx      Context           `json:"context"`
	Mrtd     string            `json:"mrtd"`     // base64
	Messages map[string]string `json:"messages"` // messageId -> base64-encoded message
}

type SigningResponse struct {
	Signatures map[string]string `json:"signatures"` // messageId -> base64-encoded signature
	PublicKey  string            `json:"publicKey"`  // base64
}

type TdxSealRequest struct {
	Id      string `json:"id"`
	Mrtd    string `json:"mrtd"`    // measurement of TD, base64
	Cfv     string `json:"cfv"`     // measurement of configuration firmware volume, base64
	Payload string `json:"payload"` // payload to seal, base64
}

type TdxSealResponse struct {
	Id            string `json:"id"`
	SealedPayload string `json:"sealedPayload"` // base64 - 12 bytes nonce || Ciphertext
}
