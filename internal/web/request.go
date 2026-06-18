// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

func decodeRequest[T any](r *http.Request) (T, error) {
	var request T

	lr := io.LimitReader(r.Body, 1024*1024)
	defer r.Body.Close()

	dec := json.NewDecoder(lr)
	var v T
	if err := dec.Decode(&v); err != nil {
		return request, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return request, errors.New("request body must contain a single JSON value")
	}

	return v, nil
}
