// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package sgx

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/edgelesssys/ego/enclave"
	"gitlab.com/real-cis/cc/betterkey/internal/common"
)

// Attestor produces and verifies SGX quotes over caller-supplied report data.
//
// Report data is the only part of a quote an application controls, so it is
// what binds a quote to something specific. Callers must only ever pass report
// data derived from key material generated inside this enclave: quoting bytes
// chosen by a remote peer would turn the enclave into a signing oracle and
// defeat any binding built on top of it.
type Attestor interface {
	// Enabled reports whether quotes are produced and required.
	Enabled() bool
	// Quote returns a remote report over reportData. It returns a nil quote
	// when attestation is disabled.
	Quote(reportData []byte) ([]byte, error)
	// VerifyQuote checks that quote is genuine, matches the configured enclave
	// identity, and was produced over expected report data.
	VerifyQuote(quote, expected []byte) error
}

type enclaveAttestor struct {
	config *common.EnclaveConfig
}

// disabledAttestor is used for non-SGX builds and tests, where no enclave is
// available. Such a node has already opted out of attestation at the TLS layer
// (see NewNodeTlsConfig), so quotes are neither produced nor checked.
type disabledAttestor struct{}

// NewAttestor returns an Attestor for the given enclave configuration. A nil
// configuration disables attestation.
func NewAttestor(config *common.EnclaveConfig) Attestor {
	if config == nil {
		return &disabledAttestor{}
	}
	return &enclaveAttestor{config: config}
}

func (a *enclaveAttestor) Enabled() bool { return true }

func (a *enclaveAttestor) Quote(reportData []byte) ([]byte, error) {
	if len(reportData) == 0 {
		return nil, errors.New("refusing to quote empty report data")
	}
	return enclave.GetRemoteReport(reportData)
}

func (a *enclaveAttestor) VerifyQuote(quote, expected []byte) error {
	if len(quote) == 0 {
		return errors.New("peer supplied no quote")
	}
	if len(expected) == 0 {
		return errors.New("no expected report data to bind against")
	}
	report, err := enclave.VerifyRemoteReport(quote)
	if err != nil {
		return fmt.Errorf("quote verification failed: %w", err)
	}
	if len(report.Data) < len(expected) {
		return fmt.Errorf("report data too short: got %d, want at least %d", len(report.Data), len(expected))
	}
	if subtle.ConstantTimeCompare(report.Data[:len(expected)], expected) != 1 {
		return errors.New("quote is not bound to this exchange")
	}
	return VerifyReport(report, a.config)
}

func (a *disabledAttestor) Enabled() bool { return false }

func (a *disabledAttestor) Quote([]byte) ([]byte, error) { return nil, nil }

func (a *disabledAttestor) VerifyQuote([]byte, []byte) error { return nil }
