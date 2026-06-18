// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package tdx

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"gitlab.com/real-cis/cc/go-trust/ccel"
	"gitlab.com/real-cis/cc/go-trust/pkg/tcg"
	"gitlab.com/real-cis/cc/go-trust/pkg/uefi"
)

const (
	// EFI secure Boot hash = Measurement of EFI Var "SecureBoot" with value 1 (enabled)
	EFISecureBootHash = "2cded0c6f453d4c6f59c5e14ec61abc6b018314540a2367cba326a52aa2b315ccc08ce68a816ce09c6ef2ac7e514ae1f"
)

// EventLog is a parsed CCEL event log.
type EventLog struct {
	*ccel.EventLogger
}

// NewEventLog decodes and parses a base64-encoded CCEL event log.
func NewEventLog(eventLogB64 string) (*EventLog, error) {
	eventLog, err := base64.StdEncoding.DecodeString(eventLogB64)
	if err != nil {
		return nil, fmt.Errorf("invalid event log: %w", err)
	}

	logger := ccel.NewEventLogger(eventLog, nil, tcg.PCClientFormat)
	if err := logger.Parse(); err != nil {
		return nil, fmt.Errorf("failed to parse event log: %w", err)
	}

	return &EventLog{EventLogger: logger}, nil
}

// Verify checks the replayed RTMRs match the quote and that Secure Boot is enabled,
// returns the CFV measurement.
func (e *EventLog) Verify(quote *TdxQuote) ([]byte, error) {
	if err := e.verifyRTMRs(quote); err != nil {
		return nil, err
	}

	enabled, err := e.secureBootEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, fmt.Errorf("secure boot is not enabled")
	}

	return e.cfv()
}

func (e *EventLog) verifyRTMRs(quote *TdxQuote) error {
	replay := e.Replay()
	rtmr0 := replay[0][tcg.AlgSHA384]
	rtmr1 := replay[1][tcg.AlgSHA384]
	rtmr2 := replay[2][tcg.AlgSHA384]

	if err := quote.VerifyRTMRs(rtmr0, rtmr1, rtmr2); err != nil {
		return fmt.Errorf("RTMR verification failed: %w", err)
	}

	return nil
}

// check if the SecureBoot UEFI variable is measured with the expected digest.
func (e *EventLog) secureBootEnabled() (bool, error) {
	for _, event := range e.FilterByEventType([]tcg.EventType{tcg.EvEfiVariableDriverConfig}) {
		uefiVar, _ := uefi.NewUefiVariableDataFromBytes(event.GetEvent())
		if uefiVar.Name.String() != "SecureBoot" {
			continue
		}
		if hex.EncodeToString(event.GetDigests()[0].Hash) != EFISecureBootHash {
			return false, fmt.Errorf("secure boot digest mismatch")
		}
		return true, nil
	}

	return false, nil
}

// cfv returns the firmware (Configuration Firmware Volume) measurement from the event log.
func (e *EventLog) cfv() ([]byte, error) {
	for _, event := range e.FilterByEventType([]tcg.EventType{tcg.EvEfiPlatformFirmwareBlob2}) {
		return event.GetDigests()[0].Hash, nil
	}

	return nil, fmt.Errorf("firmware measurement (CFV) not found in event log")
}
