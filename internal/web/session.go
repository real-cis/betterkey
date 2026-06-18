// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package web

import (
	"encoding/json"
	"net/http"

	"gitlab.com/real-cis/cc/betterkey/internal/common"
	"gitlab.com/real-cis/cc/betterkey/internal/crypto"
	"gitlab.com/real-cis/cc/betterkey/pkg/api"
)

// SessionStore for attestation session record
type SessionStore struct {
	kv common.BaseKeyStore
}

func NewSessionStore(kv common.BaseKeyStore) *SessionStore {
	return &SessionStore{kv: kv}
}

// Create generates a new session id and persists {session, nonce, payload}
func (s *SessionStore) Create(nonce []byte, payload string) (string, error) {
	sessionId := crypto.GenerateSessionID()
	jsonData, err := json.Marshal(api.AttestationRequestStore{Nonce: nonce, Payload: payload})
	if err != nil {
		return "", err
	}
	if err := s.kv.WriteWithTTL(common.STORE_PREFIX_SESSION+sessionId,
		jsonData, common.KEY_REQ_SESSION_EXPIRY_SECONDS); err != nil {
		return "", err
	}
	return sessionId, nil
}

// Get reads and decodes the session record for sessionId.
func (s *SessionStore) Get(sessionId string) (*api.AttestationRequestStore, *ErrorWithCode) {
	jsonData, err := s.kv.Read(common.STORE_PREFIX_SESSION + sessionId)
	if s.kv.HasNil(err) {
		return nil, NewError("Session expired or invalid", http.StatusUnauthorized)
	} else if err != nil {
		return nil, NewError("Failed to fetch session", http.StatusInternalServerError)
	}
	record := api.AttestationRequestStore{}
	if err = json.Unmarshal(jsonData, &record); err != nil {
		return nil, NewError("Failed to fetch payload from session store", http.StatusInternalServerError)
	}
	return &record, nil
}

// Remove a session
func (s *SessionStore) Delete(sessionId string) error {
	return s.kv.Delete(common.STORE_PREFIX_SESSION + sessionId)
}
