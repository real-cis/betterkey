// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

//go:build s3

package journal

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path"
	"time"

	s3 "gitlab.com/real-cis/libs/scaleway-s3-client/client"
)

// s3Journal persists journal records to an S3 bucket. Each record is written
// under <endpoint>/<resourceId>/<sessionId>/ as a set of files
type s3Journal struct {
	s3 *s3.Client
}

func NewJournal(cfg Config) Journal {
	if cfg.Endpoint == "" || cfg.SecretKey == "" {
		slog.Info("journal: S3 endpoint/secret key not configured; journaling disabled")
		return noopJournal{}
	}
	client := s3.NewClient(&s3.S3Config{
		Endpoint:  cfg.Endpoint,
		Region:    cfg.Region,
		AccessKey: cfg.AccessKey,
		SecretKey: cfg.SecretKey,
	})
	slog.Info("journal: S3 backend enabled", "endpoint", cfg.Endpoint)
	return &s3Journal{s3: client}
}

func (j *s3Journal) Write(ctx context.Context, rec Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	entry := Entry{
		Category:    rec.Category,
		JournalType: rec.Type,
		Description: rec.Description,
		ResourceId:  rec.ResourceId,
		Timestamp:   time.Now().UnixMilli(),
		Status:      rec.Status,
		Meta: Meta{
			QuoteSummary:    rec.QuoteSummary,
			EventLogSummary: rec.EventLogSummary,
			Mrtd:            rec.Mrtd,
			Cfv:             rec.Cfv,
		},
	}
	jsonEntry, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal journal entry: %w", err)
	}

	prefix := path.Join(rec.ResourceId, rec.SessionId)
	artifacts := []struct {
		name string
		data []byte
	}{
		{"journal.json", jsonEntry},
	}
	if rec.Quote != "" {
		artifacts = append(artifacts, struct {
			name string
			data []byte
		}{"quote.b64", []byte(rec.Quote)})
	}

	for _, a := range artifacts {
		if err := j.upload(path.Join(prefix, a.name), a.data); err != nil {
			return fmt.Errorf("upload %s: %w", a.name, err)
		}
	}
	return nil
}

// upload stages data in a temp file (the S3 client uploads from a path) and
// pushes it to the given bucket key.
func (j *s3Journal) upload(key string, data []byte) error {
	tmp, err := os.CreateTemp("", "journal-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return j.s3.Upload(key, tmp.Name())
}
