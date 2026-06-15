package api

type VerifyResponse struct {
	Nonce     string `json:"nonce"`
	SessionId string `json:"sessionId"`
}

type AttestationRequest struct {
	SessionId string `json:"sessionId"`
	Quote     string `json:"quote"`
	EventLog  string `json:"eventLog,omitempty"`
}

type AttestationRequestStore struct {
	Nonce   []byte `json:"nonce"`
	Payload string `json:"payload"`
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
