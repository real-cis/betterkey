// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package web

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"

	"gitlab.com/real-cis/cc/betterkey/internal/crypto"
	"gitlab.com/real-cis/cc/betterkey/pkg/api"
	"gitlab.com/real-cis/cc/betterkey/providers/journal"
)

// tdxSealRequestInit opens a seal session.
//
// A request that omits payload selects the wrapped flow: this node publishes an
// attested ephemeral key and the client sends the payload encrypted to it at
// finalize, so the plaintext never crosses the load balancer. A request that
// carries payload is the legacy flow, where the terminator can read it.
func (s *KeyServer) tdxSealRequestInit(req api.TdxSealRequest) (*api.VerifyResponse, *ErrorWithCode) {
	slog.Info("TDX seal request init", "id", req.Id, "mrtd", req.Mrtd, "cfv", req.Cfv,
		"wrapped", req.Payload == "")
	if req.Mrtd == "" || req.Cfv == "" {
		return nil, &ErrorWithCode{Code: http.StatusBadRequest, Message: "Missing required parameters"}
	}
	if req.Payload != "" && s.enforceKeyWrapping {
		return nil, &ErrorWithCode{Code: http.StatusBadRequest,
			Message: "payload wrapping is required: omit payload at init and send wrappedPayload at finalize"}
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, &ErrorWithCode{Code: http.StatusInternalServerError, Message: "failed to marshal request data"}
	}

	if req.Payload != "" {
		slog.Warn("client is on the legacy plaintext seal flow; the payload is readable by any " +
			"TLS terminator in the path. Set KDS_ENFORCE_KEY_WRAPPING=true once all clients are updated")
		resp, err := s.sealingChallengeResponse.Init(string(jsonData))
		if err != nil {
			return nil, &ErrorWithCode{Code: http.StatusInternalServerError, Message: "init verify request failed"}
		}
		return resp, nil
	}

	nonce := crypto.GenerateNonce(64)
	priv, pub, quote, err := newSealOffer(s.attestor, nonce)
	if err != nil {
		slog.Error("cannot publish seal offer", "error", err)
		return nil, &ErrorWithCode{Code: http.StatusInternalServerError, Message: "init verify request failed"}
	}
	sessionId, err := s.sessions.Create(nonce, string(jsonData), priv)
	if err != nil {
		return nil, &ErrorWithCode{Code: http.StatusInternalServerError, Message: "init verify request failed"}
	}

	resp := &api.VerifyResponse{
		Nonce:               base64.StdEncoding.EncodeToString(nonce),
		SessionId:           sessionId,
		KeyExchange:         sealKeyExchangeScheme,
		KeyExchangeRequired: s.enforceKeyWrapping,
		EphemeralPub:        pub,
	}
	if len(quote) > 0 {
		resp.Quote = base64.StdEncoding.EncodeToString(quote)
	}
	return resp, nil
}

func (s *KeyServer) handleTdxSealInit(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest[api.TdxSealRequest](r)
	if err != nil {
		slog.Error("failed to decode TDX seal request", "error", err)
		respondError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	response, e := s.tdxSealRequestInit(req)
	if e != nil {
		respondError(w, e.Code, e.Message)
		return
	}
	respondJSON(w, http.StatusOK, response)
}

func (s *KeyServer) handleTdxSealFinalize(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest[api.AttestationRequest](r)
	if err != nil {
		keyResponseError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	record, e := s.sessions.Get(req.SessionId)
	if e != nil {
		keyResponseError(w, e.Code, e.Message)
		return
	}

	// A session that carries an ephemeral key was opened in the wrapped flow:
	// the quote must be bound to the client's key, and the payload arrives
	// encrypted to this node's offer. The response needs no wrapping - it is
	// already ciphertext under a key derived from the TD's own measurements.
	wrapped := len(record.ServerEphemeralPriv) > 0
	expectedReportData := record.Nonce
	if wrapped {
		if err := validateEphemeralPub(req.EphemeralPub); err != nil {
			keyResponseError(w, http.StatusBadRequest, err.Error())
			return
		}
		expectedReportData = sealRequestBinding(record.Nonce, req.EphemeralPub)
	}

	_, e = s.sealingChallengeResponse.Verify(record, req.Quote, expectedReportData)
	if e != nil {
		keyResponseError(w, e.Code, e.Message)
		return
	}

	sealRequest := api.TdxSealRequest{}
	if err := json.Unmarshal([]byte(record.Payload), &sealRequest); err != nil {
		keyResponseError(w, http.StatusInternalServerError, "Failed to unmarshal seal request from store")
		return
	}

	if wrapped {
		payload, err := unwrapSealPayload(record.ServerEphemeralPriv, req.EphemeralPub,
			record.Nonce, req.WrappedPayload)
		if err != nil {
			slog.Error("rejecting seal payload", "sessionId", req.SessionId, "error", err)
			keyResponseError(w, http.StatusBadRequest, "Failed to unwrap payload")
			return
		}
		// the stored request deliberately has no payload; supply the unwrapped one
		sealRequest.Payload = base64.StdEncoding.EncodeToString(payload)
	}

	slog.Info("TDX seal request finalized")

	sealResponse, err := s.keyService.TDXSeal(sealRequest)
	if err != nil {
		s.journalSealRequest(sealRequest, req.SessionId, "Seal request failed: "+err.Error(), journal.StatusFailure)
		respondError(w, http.StatusInternalServerError, "Failed to seal payload")
		return
	}
	s.journalSealRequest(sealRequest, req.SessionId, "Seal request succeeded", journal.StatusSuccess)
	respondJSON(w, http.StatusOK, sealResponse)
}

// asynchronously records a seal-request outcome to the journal; non-blocking/best effort.
func (s *KeyServer) journalSealRequest(req api.TdxSealRequest, sessionId, description string,
	status journal.Status) {
	s.logJournal(journal.Record{
		Category:    journal.CategoryKDS,
		Type:        journal.TypeTDXSeal,
		ResourceId:  req.Id,
		SessionId:   sessionId,
		Description: description,
		Mrtd:        req.Mrtd,
		Cfv:         req.Cfv,
		Status:      status,
	})
}
