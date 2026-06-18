// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

//go:build !s3

package journal

import "log/slog"

// Returns a no-op journal. Build with -tags s3 to enable the S3 backend.
func NewJournal(_ Config) Journal {
	slog.Info("journal: no backend compiled in (build with -tags s3); journaling disabled")
	return noopJournal{}
}
