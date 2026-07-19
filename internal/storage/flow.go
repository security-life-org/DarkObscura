// Package storage persists intercepted HTTP flows. It uses BadgerDB as the hot
// store for full request/response bodies (keyed by flow ID) and SQLite as a
// searchable index over flow metadata for reporting and the UI.
package storage

import (
	"time"
)

// Flow is a single captured request/response exchange.
type Flow struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"ts"`
	Scheme    string            `json:"scheme"`
	Host      string            `json:"host"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Query     string            `json:"query"`
	ReqHeader map[string]string `json:"req_header"`
	ReqBody   []byte            `json:"req_body"`

	Status     int               `json:"status"`
	RespHeader map[string]string `json:"resp_header"`
	RespBody   []byte            `json:"resp_body"`

	DurationMS int64    `json:"duration_ms"`
	Params     []string `json:"params"` // discovered parameter names, for indexing
}

// Store is the persistence interface consumed by the proxy and engine layers.
type Store interface {
	SaveFlow(f *Flow) error
	GetFlow(id string) (*Flow, error)
	Query(q FlowQuery) ([]*FlowMeta, error)
	Close() error
}

// FlowQuery filters the metadata index. Zero-valued fields are ignored.
type FlowQuery struct {
	Host      string
	Method    string
	MinStatus int
	MaxStatus int
	Limit     int
}

// FlowMeta is the lightweight indexed projection of a Flow.
type FlowMeta struct {
	ID        string
	Timestamp time.Time
	Host      string
	Method    string
	Path      string
	Status    int
}
