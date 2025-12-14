package web

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"gitlab.com/real-cis/cc/betterkey/internal/common"
	"gitlab.com/real-cis/cc/betterkey/internal/crypto"
	"gitlab.com/real-cis/cc/betterkey/internal/tdx"
)

type ChallengeResponse interface {
	Init(requestData string) (*VerifyResponse, error)
	Verify(sessionId string, tdQuote string) (*AttestationResponse, *ErrorWithCode)
}

type AttestationVerificationProtocol struct {
	store         common.BaseKeyStore
	quoteVerifier tdx.QuoteVerifier
}

func NewAttestationProtocol(store common.BaseKeyStore, dev bool) ChallengeResponse {
	var verifier tdx.QuoteVerifier
	if dev {
		verifier = tdx.NewDevTdxQuoteVerifier()
	} else {
		verifier = tdx.NewTdxQuoteVerifier()
	}
	return &AttestationVerificationProtocol{
		store:         store,
		quoteVerifier: verifier,
	}
}

func (a *AttestationVerificationProtocol) Init(requestData string) (*VerifyResponse, error) {
	nonce := crypto.GenerateNonce(64)
	sessionId := crypto.GenerateUUID()

	jsonData, err := json.Marshal(AttestationRequestStore{Nonce: nonce, Payload: requestData})
	if err != nil {
		return nil, err
	}
	if err := a.store.WriteWithTTL(common.STORE_PREFIX_SESSION+sessionId,
		jsonData, common.KEY_REQ_SESSION_EXPIRY_SECONDS); err != nil {
		return nil, err
	}
	return &VerifyResponse{Nonce: base64.StdEncoding.EncodeToString(nonce), SessionId: sessionId}, nil
}

func DefaultStoreRead(store common.BaseKeyStore, sessionId string) (*AttestationRequestStore, *ErrorWithCode) {
	jsonData, err := store.Read(common.STORE_PREFIX_SESSION + sessionId)
	if store.HasNil(err) {
		return nil, NewError("Session expired or invalid", http.StatusUnauthorized)
	} else if err != nil {
		return nil, NewError("Failed to fetch session", http.StatusInternalServerError)
	}
	requestStore := AttestationRequestStore{}
	if err = json.Unmarshal(jsonData, &requestStore); err != nil {
		return nil, NewError("Failed to fetch payload from session store", http.StatusInternalServerError)
	}
	return &requestStore, nil
}

func (a *AttestationVerificationProtocol) Verify(sessionId string, tdQuote string) (*AttestationResponse, *ErrorWithCode) {
	requestStore, e := DefaultStoreRead(a.store, sessionId)
	if e != nil {
		return nil, e
	}
	if tdQuote == "" {
		return nil, NewError("Invalid quote", http.StatusUnauthorized)
	}
	quote, err := base64.StdEncoding.DecodeString(tdQuote)
	if err != nil {
		return nil, NewError("Invalid quote", http.StatusBadRequest)
	}

	quoteV4, err := a.quoteVerifier.Verify(quote)
	if err != nil {
		return nil, NewError("Quote verification failed", http.StatusUnauthorized)
	}

	err = a.quoteVerifier.MatchReportData(quote, requestStore.Nonce)
	if err != nil {
		return nil, NewError("verification of nonce failed", http.StatusUnauthorized)
	}

	return &AttestationResponse{Status: "success", Payload: requestStore.Payload, Quote: quoteV4}, nil
}
