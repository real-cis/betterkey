package web

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"gitlab.com/real-cis/cc/betterkey/pkg/api"
	"gitlab.com/real-cis/cc/betterkey/providers/journal"
)

func (s *KeyServer) tdxSealRequestInit(req api.TdxSealRequest) (*api.VerifyResponse, *ErrorWithCode) {
	slog.Info("TDX seal request init", "request", req)
	// Validate fields
	if req.Mrtd == "" || req.Cfv == "" || req.Payload == "" {
		return nil, &ErrorWithCode{Code: http.StatusBadRequest, Message: "Missing required parameters"}
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, &ErrorWithCode{Code: http.StatusInternalServerError, Message: "failed to marshal request data"}
	}

	resp, err := s.sealingChallengeResponse.Init(string(jsonData))
	if err != nil {
		return nil, &ErrorWithCode{Code: http.StatusInternalServerError, Message: "init verify request failed"}
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

	// Verify quote using sealing challenge-response
	_, e = s.sealingChallengeResponse.Verify(record, req.Quote)
	if e != nil {
		keyResponseError(w, e.Code, e.Message)
		return
	}

	sealRequest := api.TdxSealRequest{}
	if err := json.Unmarshal([]byte(record.Payload), &sealRequest); err != nil {
		keyResponseError(w, http.StatusInternalServerError, "Failed to unmarshal seal request from store")
		return
	}

	slog.Info("TDX seal request finalized")

	sealResponse, err := s.keyService.TDXSeal(sealRequest)
	if err != nil {
		s.journalSealRequest(sealRequest.Id, req.SessionId, "Seal request failed: "+err.Error(), journal.StatusFailure)
		respondError(w, http.StatusInternalServerError, "Failed to seal payload")
		return
	}
	s.journalSealRequest(sealRequest.Id, req.SessionId, "Seal request succeeded", journal.StatusSuccess)
	respondJSON(w, http.StatusOK, sealResponse)
}

// asynchronously records a seal-request outcome to the journal; non-blocking/best effort.
// The quote and event log belong to the authenticating client, not the VM, so they are not journaled.
func (s *KeyServer) journalSealRequest(resourceId, sessionId, payload string, status journal.Status) {
	s.logJournal(journal.Record{
		Category:   journal.CategoryKDS,
		Type:       journal.TypeTDXSeal,
		ResourceId: resourceId,
		SessionId:  sessionId,
		Payload:    payload,
		Status:     status,
	})
}
