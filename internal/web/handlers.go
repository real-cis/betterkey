// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package web

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/edgelesssys/ego/enclave"
	"gitlab.com/real-cis/cc/betterkey/pkg/api"
)

func (s *KeyServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
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
