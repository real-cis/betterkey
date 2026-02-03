package web

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"

	"gitlab.com/real-cis/cc/betterkey/internal/common"
	"gitlab.com/real-cis/cc/betterkey/internal/crypto"
	"gitlab.com/real-cis/cc/betterkey/internal/tdx"
	"gitlab.com/real-cis/cc/betterkey/pkg/api"
	"gitlab.com/real-cis/cc/go-trust/ccel"
	"gitlab.com/real-cis/cc/go-trust/pkg/tcg"
	"gitlab.com/real-cis/cc/go-trust/pkg/uefi"
)

type ChallengeResponse interface {
	Init(requestData string) (*api.VerifyResponse, error)
	Verify(sessionId string, tdQuote string, eventLog string) (*api.AttestationResponse, *ErrorWithCode)
}

const (
	// EFI secure Boot hash = Measurement of EFI Var "SecureBoot" with value 1 (enabled)
	EFISecureBootHash = "2cded0c6f453d4c6f59c5e14ec61abc6b018314540a2367cba326a52aa2b315ccc08ce68a816ce09c6ef2ac7e514ae1f"
)

type AttestationVerificationProtocol struct {
	store         common.BaseKeyStore
	quoteVerifier tdx.QuoteVerifier
	devMode       bool
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
		devMode:       dev,
	}
}

func (a *AttestationVerificationProtocol) Init(requestData string) (*api.VerifyResponse, error) {
	nonce := crypto.GenerateNonce(64)
	sessionId := crypto.GenerateUUID()

	jsonData, err := json.Marshal(api.AttestationRequestStore{Nonce: nonce, Payload: requestData})
	if err != nil {
		return nil, err
	}
	if err := a.store.WriteWithTTL(common.STORE_PREFIX_SESSION+sessionId,
		jsonData, common.KEY_REQ_SESSION_EXPIRY_SECONDS); err != nil {
		return nil, err
	}
	return &api.VerifyResponse{Nonce: base64.StdEncoding.EncodeToString(nonce), SessionId: sessionId}, nil
}

func DefaultStoreRead(store common.BaseKeyStore, sessionId string) (*api.AttestationRequestStore, *ErrorWithCode) {
	jsonData, err := store.Read(common.STORE_PREFIX_SESSION + sessionId)
	if store.HasNil(err) {
		return nil, NewError("Session expired or invalid", http.StatusUnauthorized)
	} else if err != nil {
		return nil, NewError("Failed to fetch session", http.StatusInternalServerError)
	}
	requestStore := api.AttestationRequestStore{}
	if err = json.Unmarshal(jsonData, &requestStore); err != nil {
		return nil, NewError("Failed to fetch payload from session store", http.StatusInternalServerError)
	}
	return &requestStore, nil
}

func (a *AttestationVerificationProtocol) Verify(sessionId string, tdQuote string, eventLogB64 string) (*api.AttestationResponse, *ErrorWithCode) {
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
		// TODO handle verification failures due to out of date TCBs
		// return nil, NewError("Quote verification failed", http.StatusUnauthorized)
		slog.Error("Quote verification failed", "error", err)
	}

	err = a.quoteVerifier.MatchReportData(quote, requestStore.Nonce)
	if err != nil {
		return nil, NewError("verification of nonce failed", http.StatusUnauthorized)
	}

	if a.devMode {
		// In dev mode, skip eventLog parsing
		return &api.AttestationResponse{Status: "success", Payload: requestStore.Payload, Quote: quoteV4, KeySeed: quoteV4.TdQuoteBody.MrTd}, nil
	}

	// decode eventlog base64
	eventLog, err := base64.StdEncoding.DecodeString(eventLogB64)
	if err != nil {
		return nil, NewError("Invalid event log", http.StatusBadRequest)
	}

	eventlogger := ccel.NewEventLogger(eventLog, nil, tcg.PCClientFormat)
	err = eventlogger.Parse()
	if err != nil {
		return nil, NewError("Failed to parse event log: "+err.Error(), http.StatusBadRequest)
	}

	eventlogReplay := eventlogger.Replay()
	rtmr0 := eventlogReplay[0][tcg.AlgSHA384]
	rtmr1 := eventlogReplay[1][tcg.AlgSHA384]
	rtmr2 := eventlogReplay[2][tcg.AlgSHA384]
	err = a.quoteVerifier.MatchRTMR(quoteV4, rtmr0, rtmr1, rtmr2)
	if err != nil {
		return nil, NewError("RTMR0 verification failed: "+err.Error(), http.StatusUnauthorized)
	}

	// Get CFV from event log
	// Get secure boot measurements, verify secureboot flag
	filteredEvents := eventlogger.FilterByEventType([]tcg.EventType{
		tcg.EvEfiPlatformFirmwareBlob2,
		tcg.EvEfiVariableDriverConfig,
	})

	var cfvHash []byte
	for _, event := range filteredEvents {
		eventType := event.GetEventType()

		switch eventType {
		case tcg.EvEfiPlatformFirmwareBlob2:
			cfvHash = event.GetDigests()[0].Hash
		case tcg.EvEfiVariableDriverConfig:
			uefiVar, _ := uefi.NewUefiVariableDataFromBytes(event.GetEvent())

			switch uefiVar.Name.String() {
			case "SecureBoot":
				if hex.EncodeToString(event.GetDigests()[0].Hash) != EFISecureBootHash {
					return nil, NewError("Secure Boot is not enabled", http.StatusUnauthorized)
				}
			}
		}
	}
	keySeed := DeriveSeedFromMeasurements(quoteV4.TdQuoteBody.MrTd, cfvHash)

	// TODO: log everything

	return &api.AttestationResponse{Status: "success", Payload: requestStore.Payload, Quote: quoteV4, KeySeed: keySeed}, nil
}
