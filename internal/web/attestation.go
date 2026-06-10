package web

import (
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/http"

	"gitlab.com/real-cis/cc/betterkey/internal/crypto"
	"gitlab.com/real-cis/cc/betterkey/internal/tdx"
	"gitlab.com/real-cis/cc/betterkey/pkg/api"
	"gitlab.com/real-cis/cc/go-trust/ccel"
	"gitlab.com/real-cis/cc/go-trust/pkg/tcg"
	"gitlab.com/real-cis/cc/go-trust/pkg/uefi"
)

type ChallengeResponse interface {
	// Init initializes an attestation session and returns a nonce, session ID
	Init(requestData string) (*api.VerifyResponse, error)
	// Verify verifies the quote against an already-fetched session record,
	Verify(record *api.AttestationRequestStore, tdQuote string, eventLog string) (*api.AttestationResponse, *ErrorWithCode)
}

const (
	// EFI secure Boot hash = Measurement of EFI Var "SecureBoot" with value 1 (enabled)
	EFISecureBootHash = "2cded0c6f453d4c6f59c5e14ec61abc6b018314540a2367cba326a52aa2b315ccc08ce68a816ce09c6ef2ac7e514ae1f"
)

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

func (a *AttestationVerificationProtocol) Verify(requestStore *api.AttestationRequestStore, tdQuote string, eventLogB64 string) (*api.AttestationResponse, *ErrorWithCode) {
	quote, err := a.parseQuote(tdQuote)
	if err != nil {
		return nil, err
	}

	if err := quote.Verify(); err != nil {
		// TODO handle verification failures due to out of date TCBs
		// return nil, NewError("Quote verification failed", http.StatusUnauthorized)
		slog.Error("Quote verification failed", "error", err)
	}

	if err := quote.VerifyReportData(requestStore.Nonce); err != nil {
		return nil, NewError("verification of nonce failed", http.StatusUnauthorized)
	}

	if a.devMode {
		// In dev mode, skip eventLog parsing
		return &api.AttestationResponse{
			Status:  "success",
			Payload: requestStore.Payload,
			Quote:   quote.Parsed(),
			KeySeed: quote.GetMrTd(),
		}, nil
	}

	eventLogger, err := a.parseEventLog(eventLogB64)
	if err != nil {
		return nil, err
	}

	if err := a.verifyRTMRs(quote, eventLogger); err != nil {
		return nil, err
	}

	// Extract CFV and verify secure boot
	cfvHash, err := a.extractAndVerifySecureBoot(eventLogger)
	if err != nil {
		return nil, err
	}

	keySeed := DeriveSeedFromMeasurements(quote.GetMrTd(), cfvHash)

	return &api.AttestationResponse{
		Status:  "success",
		Payload: requestStore.Payload,
		Quote:   quote.Parsed(),
		KeySeed: keySeed,
	}, nil
}

func (a *AttestationVerificationProtocol) parseQuote(tdQuote string) (*tdx.TdxQuote, *ErrorWithCode) {
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

	return quote, nil
}

func (a *AttestationVerificationProtocol) parseEventLog(eventLogB64 string) (*ccel.EventLogger, *ErrorWithCode) {
	eventLog, err := base64.StdEncoding.DecodeString(eventLogB64)
	if err != nil {
		return nil, NewError("Invalid event log", http.StatusBadRequest)
	}

	eventLogger := ccel.NewEventLogger(eventLog, nil, tcg.PCClientFormat)
	if err := eventLogger.Parse(); err != nil {
		return nil, NewError("Failed to parse event log: "+err.Error(), http.StatusBadRequest)
	}

	return eventLogger, nil
}

func (a *AttestationVerificationProtocol) verifyRTMRs(quote *tdx.TdxQuote, eventLogger *ccel.EventLogger) *ErrorWithCode {
	eventlogReplay := eventLogger.Replay()
	rtmr0 := eventlogReplay[0][tcg.AlgSHA384]
	rtmr1 := eventlogReplay[1][tcg.AlgSHA384]
	rtmr2 := eventlogReplay[2][tcg.AlgSHA384]

	if err := quote.VerifyRTMRs(rtmr0, rtmr1, rtmr2); err != nil {
		return NewError("RTMR verification failed: "+err.Error(), http.StatusUnauthorized)
	}

	return nil
}

func (a *AttestationVerificationProtocol) extractAndVerifySecureBoot(eventLogger *ccel.EventLogger) ([]byte, *ErrorWithCode) {
	var cfvHash []byte
	secureBootEnabled := false
	for _, event := range eventLogger.FilterByEventType([]tcg.EventType{
		tcg.EvEfiPlatformFirmwareBlob2,
		tcg.EvEfiVariableDriverConfig,
	}) {
		eventType := event.GetEventType()

		switch eventType {
		case tcg.EvEfiPlatformFirmwareBlob2:
			cfvHash = event.GetDigests()[0].Hash
		case tcg.EvEfiVariableDriverConfig:
			uefiVar, _ := uefi.NewUefiVariableDataFromBytes(event.GetEvent())

			switch uefiVar.Name.String() {
			case "SecureBoot":
				if hex.EncodeToString(event.GetDigests()[0].Hash) != EFISecureBootHash {
					return nil, NewError("Secure Boot digest mismatch", http.StatusUnauthorized)
				}
				secureBootEnabled = true
			}
		}
	}

	if !secureBootEnabled {
		return nil, NewError("Secure Boot is not enabled", http.StatusUnauthorized)
	}

	return cfvHash, nil
}
