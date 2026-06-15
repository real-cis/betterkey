// Backend-agnostic abstraction for persisting journal records
package journal

import (
	"context"
	"encoding/json"
)

type Category string

type Type string

type Status string

const (
	CategoryKDS    Category = "KDS"
	TypeKeyRequest Type     = "KEY_REQUEST"
	TypeTDXSeal    Type     = "TDX_SEAL"
	StatusSuccess  Status   = "SUCCESS"
	StatusFailure  Status   = "FAIL"
)

// Entry json persisted for each journal record.
type Entry struct {
	Category    Category `json:"category"`
	JournalType Type     `json:"journalType"`
	Description string   `json:"description"`
	ResourceId  string   `json:"resourceId"`
	Timestamp   int64    `json:"timeStamp"` // Unix epoch milliseconds
	Status      Status   `json:"status"`
	Meta        Meta     `json:"meta"`
}

// Optional structured artifacts embedded alongside a journal entry. Binary
// fields are serialized as base64
type Meta struct {
	QuoteSummary    json.RawMessage `json:"quote,omitempty"`    // parsed quote header/body
	EventLogSummary json.RawMessage `json:"eventlog,omitempty"` // event log summary
	Mrtd            string          `json:"mrtd,omitempty"`     // measurement of the TD, base64
	Cfv             string          `json:"cfv,omitempty"`      // configuration firmware volume digest, base64
}

// Single journal event together with the artifacts to persist.
type Record struct {
	Category    Category
	Type        Type
	ResourceId  string
	SessionId   string
	Description string
	Status      Status

	// TDX quote in base64
	Quote           string
	QuoteSummary    json.RawMessage
	EventLogSummary json.RawMessage
	Mrtd            string
	Cfv             string
}

// Backend-agnostic journal configuration, mapped from internal/common
type Config struct {
	Endpoint  string
	Region    string
	AccessKey string
	SecretKey string
}

// Journal persists journal records to a backing store.
type Journal interface {
	Write(ctx context.Context, rec Record) error
}

// noopJournal is used when journaling is disabled or no backend is compiled in.
type noopJournal struct{}

func (noopJournal) Write(context.Context, Record) error { return nil }
