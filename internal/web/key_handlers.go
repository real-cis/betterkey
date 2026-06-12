package web

import (
	"crypto/elliptic"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"gitlab.com/real-cis/cc/betterkey/internal/tdx"
	"gitlab.com/real-cis/cc/betterkey/pkg/api"
	"gitlab.com/real-cis/cc/betterkey/providers/journal"
)

// journalWriteTimeout bounds a single (asynchronous) journal write.
const journalWriteTimeout = 30 * time.Second

func (s *KeyServer) keyRequestInit(req api.KeyRequest) (*api.VerifyResponse, *ErrorWithCode) {
	if req.Type == "" || req.Id == "" {
		return nil, &ErrorWithCode{Code: http.StatusBadRequest, Message: "Invalid request parameters"}
	}
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, &ErrorWithCode{Code: http.StatusInternalServerError, Message: "failed to marshal request data"}
	}
	resp, err := s.challengeResponse.Init(string(jsonData))
	if err != nil {
		return nil, &ErrorWithCode{Code: http.StatusInternalServerError, Message: "init verify request failed"}
	}
	return resp, nil
}

func (s *KeyServer) keyRequestFinalize(id string, keyType api.KeyType, ctx api.Context,
	seed []byte) (*api.KeyResponse, *ErrorWithCode) {
	slog.Info("key derivation request", "type", keyType, "id", id, "context", ctx)

	var key any
	var err error
	switch keyType {
	case api.Symmetric:
		key, err = s.keyService.DeriveHKDF(id, seed, ctx)
	case api.X25519:
		key, err = s.keyService.DeriveX25519(id, seed, ctx)
	case api.P256:
		key, err = s.keyService.DeriveECDSA(id, seed, ctx, elliptic.P256(), 32)
	case api.P384:
		key, err = s.keyService.DeriveECDSA(id, seed, ctx, elliptic.P384(), 48)
	case api.RSA:
		key, err = s.keyService.CreateRSA(id)
	default:
		return nil, &ErrorWithCode{Code: http.StatusBadRequest, Message: "invalid key type"}
	}
	if err != nil {
		slog.Error("key derivation failed", "error", err)
		return nil, &ErrorWithCode{Code: http.StatusInternalServerError, Message: "key derivation failed"}
	}
	return &api.KeyResponse{Key: key, Verified: true}, nil
}

func (s *KeyServer) handleKeyRequestInit(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest[api.KeyRequest](r)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	response, e := s.keyRequestInit(req)
	if e != nil {
		respondError(w, e.Code, e.Message)
		return
	}
	respondJSON(w, http.StatusOK, response)
}

func (s *KeyServer) handleKeyRequestFinalize(w http.ResponseWriter, r *http.Request) {
	attestationRequest, err := decodeRequest[api.AttestationRequest](r)
	if err != nil {
		keyResponseError(w, http.StatusBadRequest, "Invalid Request")
		return
	}

	// Read the session once and parse the key request up front
	record, e := s.sessions.Get(attestationRequest.SessionId)
	if e != nil {
		keyResponseError(w, e.Code, e.Message)
		return
	}
	keyRequest := api.KeyRequest{}
	if err := json.Unmarshal([]byte(record.Payload), &keyRequest); err != nil {
		keyResponseError(w, http.StatusInternalServerError, "Failed to unmarshal key request from store")
		return
	}
	if keyRequest.Id == "" {
		keyResponseError(w, http.StatusBadRequest, "Missing id")
		return
	}

	// Verify the quote against the already-fetched record
	quote, e := s.challengeResponse.Verify(record, attestationRequest.Quote)
	if e != nil {
		keyResponseError(w, e.Code, e.Message)
		return
	}

	// Verify the event log against the quote and extract the CFV
	eventLog, err := tdx.NewEventLog(attestationRequest.EventLog)
	if err != nil {
		keyResponseError(w, http.StatusUnauthorized, err.Error())
		return
	}
	cfv, err := eventLog.Verify(quote)
	if err != nil {
		keyResponseError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// remove the session after a successful verification.
	if err := s.sessions.Delete(attestationRequest.SessionId); err != nil {
		slog.Warn("failed to delete finalized session", "sessionId", attestationRequest.SessionId, "error", err)
	}

	// Derive the key seed from the verified TDX measurements
	keySeed := DeriveSeedFromMeasurements(quote.GetMrTd(), cfv)
	keyResponse, e := s.keyRequestFinalize(keyRequest.Id, keyRequest.Type, keyRequest.Ctx, keySeed)
	if e != nil {
		s.journalKeyRequest(keyRequest.Id, attestationRequest.SessionId, "Key request failed: "+e.Message,
			attestationRequest.Quote, marshalEventLogSummary(eventLog), journal.StatusFailure)
		respondError(w, e.Code, e.Message)
		return
	}
	s.journalKeyRequest(keyRequest.Id, attestationRequest.SessionId, "Key request succeeded",
		attestationRequest.Quote, marshalEventLogSummary(eventLog), journal.StatusSuccess)
	respondJSON(w, http.StatusOK, keyResponse)
}

// marshalEventLogSummary returns the event log summary as JSON; best effort, empty on error.
func marshalEventLogSummary(eventLog *tdx.EventLog) string {
	summary, err := json.Marshal(eventLog.Summary())
	if err != nil {
		slog.Warn("failed to marshal event log summary", "error", err)
		return ""
	}
	return string(summary)
}

// asynchronously records a key-request outcome to the journal.; non-blocking/best effort
func (s *KeyServer) journalKeyRequest(resourceId, sessionId, payload, quote, eventLog string, status journal.Status) {
	s.logJournal(journal.Record{
		Category:   journal.CategoryKDS,
		Type:       journal.TypeKeyRequest,
		ResourceId: resourceId,
		SessionId:  sessionId,
		Payload:    payload,
		Quote:      quote,
		EventLog:   eventLog,
		Status:     status,
	})
}
