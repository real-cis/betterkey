// Backend-agnostic abstraction for persisting journal records
package journal

import "context"

type Category string

type Type string

const (
	CategoryKDS    Category = "KDS"
	TypeKeyRequest Type     = "KEY_REQUEST"
)

// Entry json persisted for each journal record.
type Entry struct {
	Category    Category `json:"category"`
	JournalType Type     `json:"journalType"`
	Payload     string   `json:"payload"`
	ResourceId  string   `json:"resourceId"`
	Timestamp   int64    `json:"timeStamp"` // Unix epoch milliseconds
}

// Single journal event together with the artifacts to persist.
type Record struct {
	Category   Category
	Type       Type
	ResourceId string
	SessionId  string
	Payload    string

	// TDX quote in base64
	Quote    string
	EventLog string
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
