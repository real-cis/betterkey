package web

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/enclave"
	"github.com/go-chi/chi/v5"
	"github.com/google/go-tdx-guest/proto/tdx"
	"gitlab.com/real-cis/cc/betterkey/internal/sgx"
)

func (s *HTTPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *HTTPServer) handleVerifyRequest(w http.ResponseWriter, r *http.Request) {
	response, err := s.challengeResponse.Init("")
	if err != nil {
		http.Error(w, "init verify request failed", http.StatusInternalServerError)
		return
	}
	respondJSON(w, http.StatusOK, response)
}

func (s *HTTPServer) handleVerifyQuote(w http.ResponseWriter, r *http.Request) {
	req, e := decodeRequest[AttestationRequest](r)
	if e != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	response, err := s.challengeResponse.Verify(req.SessionId, req.Quote)
	if err != nil {
		keyResponseError(w, err.Code, err.Message)
		return
	}

	respondJSON(w, http.StatusOK, response)
}

func (s *HTTPServer) keyRequestInit(req KeyRequest) (*VerifyResponse, *ErrorWithCode) {
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

func (s *HTTPServer) keyRequestVerify(r *http.Request) (*AttestationResponse, *ErrorWithCode) {
	req, err := decodeRequest[AttestationRequest](r)
	if err != nil {
		return nil, &ErrorWithCode{Code: http.StatusBadRequest, Message: "Invalid request"}
	}
	// Verify quote
	return s.challengeResponse.Verify(req.SessionId, req.Quote)
}

func (s *HTTPServer) keyRequestFinalize(id string, keyType KeyType, ctx Context,
	mrtd []byte, quote *tdx.QuoteV4) (*KeyResponse, *ErrorWithCode) {
	slog.Info("key derivation request", "type", keyType, "id", id, "context", ctx)
	// Verify policy, if any
	verified, err := s.policyService.Verify(id, quote)
	if err != nil || !verified {
		return nil, &ErrorWithCode{Code: http.StatusUnauthorized, Message: "Policy verification failed"}
	}
	var key any
	switch keyType {
	case Symmetric:
		key, err = s.keyService.DeriveHKDF(id, mrtd, ctx)
	case X25519:
		key, err = s.keyService.DeriveX25519(id, mrtd, ctx)
	case P256:
		key, err = s.keyService.DeriveECDSA(id, mrtd, ctx, elliptic.P256(), 32)
	case P384:
		key, err = s.keyService.DeriveECDSA(id, mrtd, ctx, elliptic.P384(), 48)
	case RSA:
		key, err = s.keyService.CreateRSA(id)
	default:
		return nil, &ErrorWithCode{Code: http.StatusBadRequest, Message: "invalid key type"}
	}
	if err != nil {
		slog.Error("key derivation failed", "error", err)
		return nil, &ErrorWithCode{Code: http.StatusInternalServerError, Message: "key derivation failed"}
	}
	return &KeyResponse{Key: key, Verified: true}, nil
}

func (s *HTTPServer) handleKeyRequestInit(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest[KeyRequest](r)
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

func (s *HTTPServer) handleKeyRequestFinalize(w http.ResponseWriter, r *http.Request) {
	response, e := s.keyRequestVerify(r)
	if e != nil {
		keyResponseError(w, e.Code, e.Message)
		return
	}
	keyRequest := KeyRequest{}
	if err := json.Unmarshal([]byte(response.Payload), &keyRequest); err != nil {
		keyResponseError(w, http.StatusInternalServerError, "Failed to unmarshal key request from store")
		return
	}
	keyResponse, e := s.keyRequestFinalize(keyRequest.Id, keyRequest.Type, keyRequest.Ctx, response.Quote.TdQuoteBody.MrTd, response.Quote)
	if e != nil {
		respondError(w, e.Code, e.Message)
		return
	}
	respondJSON(w, http.StatusOK, keyResponse)
}

func (s *HTTPServer) handleSgxQuoteVerify(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest[SGXQuote](r)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	quote, err := base64.StdEncoding.DecodeString(req.SignedQuote)
	if err != nil {
		respondError(w, http.StatusBadRequest, fmt.Sprintf("bad quote format:%v", err))
		return
	}
	response, err := sgx.ValidateSignedQuote(quote)

	if err != nil {
		if err == attestation.ErrTCBLevelInvalid {
			slog.Error("attestation.ErrTCBLevelInvalid accepted", "report", response)
			respondJSON(w, http.StatusOK, response)
		} else {
			respondError(w, http.StatusBadRequest, fmt.Sprintf("bad quote :%v", err))
		}
	} else {
		slog.Info("enclave.VerifyRemoteReport ok", "report", response)
		respondJSON(w, http.StatusOK, response)
	}
}

func (s *HTTPServer) handleGenerateAttestation(w http.ResponseWriter, _ *http.Request) {
	endpoint := net.JoinHostPort(s.NodeHost, fmt.Sprintf("%d", s.Port))
	slog.Info("collecting server certificate", "endpoint", endpoint)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", endpoint, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         s.Domain,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("cannot connect to:%v,error:%v", endpoint, err))
		return
	}

	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	slog.Info("got certs from remote", "length", len(certs))
	if len(certs) == 0 {
		respondError(w, http.StatusInternalServerError, "no peer certificates")
		return
	}
	certHash := sha256.Sum256(certs[0].Raw)
	slog.Info("server cert", "data(base64)", base64.StdEncoding.EncodeToString(certs[0].Raw))
	slog.Info("expected data in verified report(hex)", "data", hex.EncodeToString(certHash[:]))
	att, err := enclave.GetRemoteReport(certHash[:])
	if err != nil {
		respondError(w, http.StatusBadRequest, fmt.Sprintf("cannot generate quote:%v", err))
		return
	}

	respondJSON(w, http.StatusOK, SGXQuote{SignedQuote: base64.StdEncoding.EncodeToString(att)})
}

func (s *HTTPServer) handlePolicyUpdate(w http.ResponseWriter, r *http.Request) {
	request, err := decodeRequest[PolicyUpdateRequest](r)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	err = s.policyService.Upsert(request)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update policy")
		return
	}

	respondJSON(w, http.StatusOK, "Policy updated successfully")
}

func (s *HTTPServer) handleKeyDelete(w http.ResponseWriter, r *http.Request) {
	keyId := chi.URLParam(r, "id")
	// remove keys
	err := s.keyService.RemoveRSA(keyId)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete key")
		return
	}
	// remove policies
	err = s.policyService.Delete(keyId)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete associated policies")
		return
	}

	respondJSON(w, http.StatusOK, "Key deleted successfully")
}

func (s *HTTPServer) handleSigningRequest(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest[SigningRequest](r)
	if err != nil {
		slog.Error("failed to decode signing request", "error", err)
		respondError(w, http.StatusBadRequest, "Invalid request")
		return
	}
	slog.Info("signing request received", "keyId", req.Id)
	signingResponse, err := s.keyService.SignWithECDSA(req)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to sign data")
		return
	}
	respondJSON(w, http.StatusOK, signingResponse)
}
