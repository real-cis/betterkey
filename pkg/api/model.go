package api

import "github.com/google/go-tdx-guest/proto/tdx"

type VerifyResponse struct {
	Nonce     string `json:"nonce"`
	SessionId string `json:"sessionId"`
}

type AttestationRequest struct {
	SessionId string `json:"sessionId"`
	Quote     string `json:"quote"`
}

type AttestationResponse struct {
	Status  string       `json:"status"`
	Payload string       `json:"payload"`
	Quote   *tdx.QuoteV4 `json:"quote"`
}

type AttestationRequestStore struct {
	Nonce   []byte `json:"nonce"`
	Payload string `json:"payload"`
}

type PolicyUpdateRequest struct {
	Id     string `json:"id"`
	Mrtd   string `json:"mrtd"`
	Kernel string `json:"kernel,omitempty"`
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
