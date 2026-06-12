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
	sessions *SessionStore
	devMode  bool
}

func NewAttestationProtocol(sessions *SessionStore, dev bool) ChallengeResponse {
	return &AttestationVerificationProtocol{
		sessions: sessions,
		devMode:  dev,
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

	quote, err := tdx.NewTdxQuoteWithMode(quoteBytes, a.devMode)
	if err != nil {
		return nil, NewError("Failed to parse quote: "+err.Error(), http.StatusBadRequest)
	}

	if err := quote.Verify(); err != nil {
		// TODO handle verification failures due to out of date TCBs
		// return nil, NewError("Quote verification failed", http.StatusUnauthorized)
		slog.Error("Quote verification failed", "error", err)
	}

	if err := quote.VerifyReportData(requestStore.Nonce); err != nil {
		return nil, NewError("verification of nonce failed", http.StatusUnauthorized)
	}

	return quote, nil
}
