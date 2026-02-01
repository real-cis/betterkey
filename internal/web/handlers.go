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
	"gitlab.com/real-cis/cc/betterkey/pkg/api"
)

func (s *KeyServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *KeyServer) handleVerifyRequest(w http.ResponseWriter, r *http.Request) {
	response, err := s.challengeResponse.Init("")
	if err != nil {
		http.Error(w, "init verify request failed", http.StatusInternalServerError)
		return
	}
	respondJSON(w, http.StatusOK, response)
}

func (s *KeyServer) handleVerifyQuote(w http.ResponseWriter, r *http.Request) {
	req, e := decodeRequest[api.AttestationRequest](r)
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

func (s *KeyServer) keyRequestVerify(r *http.Request) (*api.AttestationResponse, *ErrorWithCode) {
	req, err := decodeRequest[api.AttestationRequest](r)
	if err != nil {
		return nil, &ErrorWithCode{Code: http.StatusBadRequest, Message: "Invalid request"}
	}
	// Verify quote
	return s.challengeResponse.Verify(req.SessionId, req.Quote)
}

func (s *KeyServer) keyRequestFinalize(id string, keyType api.KeyType, ctx api.Context,
	mrtd []byte, quote *tdx.QuoteV4) (*api.KeyResponse, *ErrorWithCode) {
	slog.Info("key derivation request", "type", keyType, "id", id, "context", ctx)
	// Verify policy, if any
	verified, err := s.policyService.Verify(id, quote)
	if err != nil || !verified {
		return nil, &ErrorWithCode{Code: http.StatusUnauthorized, Message: "Policy verification failed"}
	}
	var key any
	switch keyType {
	case api.Symmetric:
		key, err = s.keyService.DeriveHKDF(id, mrtd, ctx)
	case api.X25519:
		key, err = s.keyService.DeriveX25519(id, mrtd, ctx)
	case api.P256:
		key, err = s.keyService.DeriveECDSA(id, mrtd, ctx, elliptic.P256(), 32)
	case api.P384:
		key, err = s.keyService.DeriveECDSA(id, mrtd, ctx, elliptic.P384(), 48)
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
	response, e := s.keyRequestVerify(r)
	if e != nil {
		keyResponseError(w, e.Code, e.Message)
		return
	}
	keyRequest := api.KeyRequest{}
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

func (s *KeyServer) handleSgxQuoteVerify(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest[api.SGXQuote](r)
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

func (s *KeyServer) handleGenerateAttestation(w http.ResponseWriter, _ *http.Request) {
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

	respondJSON(w, http.StatusOK, api.SGXQuote{SignedQuote: base64.StdEncoding.EncodeToString(att)})
}

func (s *KeyServer) handleKeyDelete(w http.ResponseWriter, r *http.Request) {
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

func (s *KeyServer) handleSigningRequest(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest[api.SigningRequest](r)
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

func (s *KeyServer) tdxSealRequestInit(req api.TdxSealRequest) (*api.VerifyResponse, *ErrorWithCode) {
	// Validate fields
	if req.Mrtd == "" || req.Cfv == "" || req.SecurebootPK == "" || req.SecurebootKEK == "" ||
		req.SecurebootDB == "" || req.SecurebootDBX == "" || req.Payload == "" {
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

func (s *KeyServer) tdxSealRequestVerify(r *http.Request) (*api.AttestationResponse, *ErrorWithCode) {
	req, err := decodeRequest[api.AttestationRequest](r)
	if err != nil {
		return nil, &ErrorWithCode{Code: http.StatusBadRequest, Message: "Invalid request"}
	}
	// Verify quote using sealing challenge-response
	return s.sealingChallengeResponse.Verify(req.SessionId, req.Quote)
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
	response, e := s.tdxSealRequestVerify(r)
	if e != nil {
		keyResponseError(w, e.Code, e.Message)
		return
	}

	sealRequest := api.TdxSealRequest{}
	if err := json.Unmarshal([]byte(response.Payload), &sealRequest); err != nil {
		keyResponseError(w, http.StatusInternalServerError, "Failed to unmarshal seal request from store")
		return
	}

	slog.Info("TDX seal request finalized")

	sealResponse, err := s.keyService.TDXSeal(sealRequest)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to seal payload")
		return
	}

	respondJSON(w, http.StatusOK, sealResponse)
}
