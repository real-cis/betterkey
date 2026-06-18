// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package cert

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/caddyserver/certmagic"
	"gitlab.com/real-cis/cc/betterkey/internal/common"
)

type AcmeConfig struct {
	Domain       string
	DnsProvider  certmagic.DNSProvider
	AcmeOwner    string
	AcmeProvider string
	KVStore      common.KeyStore
	NodeId       string
	RetryDelay   int
	RetryCount   int
}

func (a *AcmeConfig) Setup() *certmagic.Config {
	certmagic.Default.Storage = NewCertStorage(a.KVStore, a.NodeId)
	certmagic.DefaultACME.CA = a.AcmeProvider
	certmagic.DefaultACME.Email = a.AcmeOwner
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.DisableHTTPChallenge = true
	certmagic.DefaultACME.DisableTLSALPNChallenge = true
	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider: a.DnsProvider,
		},
	}

	cm := certmagic.NewDefault()

	for range a.RetryCount {
		err := cm.ManageSync(context.Background(), []string{a.Domain})
		if err != nil {
			slog.Error(fmt.Sprintf("Error managing certificate: %v", err))
		} else {
			slog.Info("Certificate managed successfully")
			break
		}
		time.Sleep(time.Duration(a.RetryDelay) * time.Second)
	}

	return cm
}
