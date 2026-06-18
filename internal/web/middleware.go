// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package web

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		slog.Info(fmt.Sprintf("%s %s %s", r.Method, r.URL.Path, time.Since(start)))
	})
}

func DefaultHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}
