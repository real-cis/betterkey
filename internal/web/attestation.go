package web

import (
	"encoding/base64"
	"log/slog"
	"net/http"

	"gitlab.com/real-cis/cc/betterkey/internal/crypto"
	"gitlab.com/real-cis/cc/betterkey/internal/tdx"
	"gitlab.com/real-cis/cc/betterkey/pkg/api"
)

type ChallengeResponse interface {
	// Init initializes an attestation session and returns a nonce, session ID
	Init(requestData string) (*api.VerifyResponse, error)
	// Verify verifies the quote and that its report data matches the session nonce.
	Verify(record *api.AttestationRequestStore, tdQuote string) (*tdx.TdxQuote, *ErrorWithCode)
}

type AttestationVerificationProtocol struct {
	sessions           *SessionStore
	devMode            bool
	enforceQuoteVerify bool
}

func NewAttestationProtocol(sessions *SessionStore, dev bool, enforceQuoteVerify bool) ChallengeResponse {
	return &AttestationVerificationProtocol{
		sessions:           sessions,
		devMode:            dev,
		enforceQuoteVerify: enforceQuoteVerify,
	}
}

func (a *AttestationVerificationProtocol) Init(requestData string) (*api.VerifyResponse, error) {
	nonce := crypto.GenerateNonce(64)
	sessionId, err := a.sessions.Create(nonce, requestData)
	if err != nil {
		return nil, err
	}
	return &api.VerifyResponse{Nonce: base64.StdEncoding.EncodeToString(nonce), SessionId: sessionId}, nil
}

func (a *AttestationVerificationProtocol) Verify(requestStore *api.AttestationRequestStore, tdQuote string) (*tdx.TdxQuote, *ErrorWithCode) {
	if tdQuote == "" {
		return nil, NewError("Invalid quote", http.StatusUnauthorized)
	}

	quoteBytes, err := base64.StdEncoding.DecodeString(tdQuote)
	if err != nil {
		return nil, NewError("Invalid quote", http.StatusBadRequest)
	}

	quote, err := tdx.NewTdxQuote(quoteBytes)
	if err != nil {
		return nil, NewError("Failed to parse quote: "+err.Error(), http.StatusBadRequest)
	}

	if err := quote.Verify(); err != nil {
		// log errors
		slog.Error("Quote verification failed", "error", err, "enforced", a.enforceQuoteVerify)
		if a.enforceQuoteVerify {
			return nil, NewError("Quote verification failed", http.StatusUnauthorized)
		}
	}

	if err := quote.VerifyReportData(requestStore.Nonce); err != nil && !a.devMode {
		return nil, NewError("verification of nonce failed", http.StatusUnauthorized)
	}

	return quote, nil
}
