package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	badger "github.com/dgraph-io/badger/v4"
	_ "modernc.org/sqlite"
)

// hybridStore combines a Badger KV store (full flow bodies) with a SQLite index
// (searchable metadata). It satisfies Store.
type hybridStore struct {
	kv  *badger.DB
	idx *sql.DB
}

// Open creates/opens a store rooted at dir. Badger data lives in dir/badger and
// the SQLite index in dir/index.db.
func Open(dir string) (Store, error) {
	opts := badger.DefaultOptions(dir + "/badger").WithLoggingLevel(badger.ERROR)
	kv, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("storage: open badger: %w", err)
	}
	idx, err := sql.Open("sqlite", dir+"/index.db")
	if err != nil {
		kv.Close()
		return nil, fmt.Errorf("storage: open sqlite: %w", err)
	}
	if _, err := idx.Exec(schema); err != nil {
		kv.Close()
		idx.Close()
		return nil, fmt.Errorf("storage: init schema: %w", err)
	}
	return &hybridStore{kv: kv, idx: idx}, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS flows (
    id      TEXT PRIMARY KEY,
    ts      INTEGER NOT NULL,
    host    TEXT NOT NULL,
    method  TEXT NOT NULL,
    path    TEXT NOT NULL,
    status  INTEGER NOT NULL,
    params  TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_host ON flows(host);
CREATE INDEX IF NOT EXISTS idx_flows_status ON flows(status);
`

func (s *hybridStore) SaveFlow(f *Flow) error {
	blob, err := json.Marshal(f)
	if err != nil {
		return err
	}
	err = s.kv.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("flow:"+f.ID), blob)
	})
	if err != nil {
		return fmt.Errorf("storage: kv save: %w", err)
	}
	_, err = s.idx.Exec(
		`INSERT OR REPLACE INTO flows(id, ts, host, method, path, status, params) VALUES(?,?,?,?,?,?,?)`,
		f.ID, f.Timestamp.UnixNano(), f.Host, f.Method, f.Path, f.Status, strings.Join(f.Params, ","),
	)
	if err != nil {
		return fmt.Errorf("storage: idx save: %w", err)
	}
	return nil
}

func (s *hybridStore) GetFlow(id string) (*Flow, error) {
	var f Flow
	err := s.kv.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("flow:" + id))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &f)
		})
	})
	if err != nil {
		return nil, err
	}
	return &f, nil
}

func (s *hybridStore) Query(q FlowQuery) ([]*FlowMeta, error) {
	var (
		sb   strings.Builder
		args []any
	)
	sb.WriteString(`SELECT id, ts, host, method, path, status FROM flows WHERE 1=1`)
	if q.Host != "" {
		sb.WriteString(" AND host = ?")
		args = append(args, q.Host)
	}
	if q.Method != "" {
		sb.WriteString(" AND method = ?")
		args = append(args, q.Method)
	}
	if q.MinStatus > 0 {
		sb.WriteString(" AND status >= ?")
		args = append(args, q.MinStatus)
	}
	if q.MaxStatus > 0 {
		sb.WriteString(" AND status <= ?")
		args = append(args, q.MaxStatus)
	}
	sb.WriteString(" ORDER BY ts DESC")
	if q.Limit > 0 {
		sb.WriteString(" LIMIT ?")
		args = append(args, q.Limit)
	}
	rows, err := s.idx.Query(sb.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*FlowMeta
	for rows.Next() {
		var (
			m  FlowMeta
			ts int64
		)
		if err := rows.Scan(&m.ID, &ts, &m.Host, &m.Method, &m.Path, &m.Status); err != nil {
			return nil, err
		}
		m.Timestamp = time.Unix(0, ts)
		out = append(out, &m)
	}
	return out, rows.Err()
}

func (s *hybridStore) Close() error {
	var firstErr error
	if err := s.idx.Close(); err != nil {
		firstErr = err
	}
	if err := s.kv.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
