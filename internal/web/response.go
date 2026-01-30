package web

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"gitlab.com/real-cis/cc/betterkey/pkg/api"
)

type ErrorWithCode struct {
	Message string
	Code    int
}

func (e *ErrorWithCode) Error() string {
	return e.Message
}

func NewError(msg string, code int) *ErrorWithCode {
	return &ErrorWithCode{
		Code:    code,
		Message: msg,
	}
}

func respondJSON(w http.ResponseWriter, code int, v any) {
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Info("Failed to encode error response", "err", err)
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

func respondError(w http.ResponseWriter, code int, message string) {
	slog.Error("request error", "code", code, "message", message)
	w.Header().Set("Content-Type", "application/json")
	respondJSON(w, code, map[string]string{"error": message})
}

func keyResponseError(w http.ResponseWriter, status int, message string) {
	slog.Error("key request error", "status", status, "message", message)
	resp := api.KeyResponse{Message: message, Verified: false, Key: nil}
	respondJSON(w, status, resp)
}
