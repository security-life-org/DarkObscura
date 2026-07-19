// Package findings is DarkObscura's cross-scan memory. A scanner without history
// re-reports the same issues every run and cannot tell a regression from noise.
// findings persists confirmed results in SQLite (modernc, already a platform
// dependency), deduplicates them by a stable fingerprint (target|param|class),
// answers "what is new since the last scan of this target", and supports a
// suppression allowlist so a triaged false-positive or accepted risk stops
// reappearing. It is deliberately decoupled from internal/exploit (plain Record
// struct) to avoid an import cycle.
package findings

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Record is a storable finding, independent of the exploit package's type.
type Record struct {
	Fingerprint string
	Target      string
	Param       string
	Class       string
	Severity    string
	Payload     string
	VerifiedVia string
	FirstSeen   time.Time
	LastSeen    time.Time
}

// Fingerprint returns the stable dedup key for a finding.
func Fingerprint(target, param, class string) string {
	sum := sha256.Sum256([]byte(target + "|" + param + "|" + class))
	return hex.EncodeToString(sum[:16])
}

// Store is the persistent findings database.
type Store struct {
	db *sql.DB
}

const findingsSchema = `
CREATE TABLE IF NOT EXISTS findings (
    fingerprint TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    param       TEXT,
    class       TEXT NOT NULL,
    severity    TEXT,
    payload     TEXT,
    verified_via TEXT,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS suppressions (
    fingerprint TEXT PRIMARY KEY,
    reason      TEXT,
    ts          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
`

// Open creates/opens the findings store at path (a SQLite file).
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(findingsSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("findings: init schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// Upsert records a batch of findings and returns the subset that are NEW (never
// seen before this call), skipping any that are suppressed. Existing findings
// have their last_seen bumped.
func (s *Store) Upsert(recs []Record) ([]Record, error) {
	now := time.Now()
	var fresh []Record
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	for _, r := range recs {
		if r.Fingerprint == "" {
			r.Fingerprint = Fingerprint(r.Target, r.Param, r.Class)
		}
		var sup int
		if err := tx.QueryRow(`SELECT COUNT(1) FROM suppressions WHERE fingerprint=?`, r.Fingerprint).Scan(&sup); err != nil {
			return nil, err
		}
		if sup > 0 {
			continue // triaged / accepted — never resurface
		}
		var existing int
		if err := tx.QueryRow(`SELECT COUNT(1) FROM findings WHERE fingerprint=?`, r.Fingerprint).Scan(&existing); err != nil {
			return nil, err
		}
		if existing == 0 {
			r.FirstSeen, r.LastSeen = now, now
			fresh = append(fresh, r)
			if _, err := tx.Exec(
				`INSERT INTO findings(fingerprint,target,param,class,severity,payload,verified_via,first_seen,last_seen)
				 VALUES(?,?,?,?,?,?,?,?,?)`,
				r.Fingerprint, r.Target, r.Param, r.Class, r.Severity, r.Payload, r.VerifiedVia,
				now.UnixNano(), now.UnixNano()); err != nil {
				return nil, err
			}
		} else {
			if _, err := tx.Exec(`UPDATE findings SET last_seen=? WHERE fingerprint=?`, now.UnixNano(), r.Fingerprint); err != nil {
				return nil, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return fresh, nil
}

// History returns all stored findings for a target (host substring match),
// newest last_seen first.
func (s *Store) History(target string) ([]Record, error) {
	rows, err := s.db.Query(
		`SELECT fingerprint,target,param,class,severity,payload,verified_via,first_seen,last_seen
		 FROM findings WHERE target LIKE ? ORDER BY last_seen DESC`, "%"+target+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		var fs, ls int64
		if err := rows.Scan(&r.Fingerprint, &r.Target, &r.Param, &r.Class, &r.Severity,
			&r.Payload, &r.VerifiedVia, &fs, &ls); err != nil {
			return nil, err
		}
		r.FirstSeen, r.LastSeen = time.Unix(0, fs), time.Unix(0, ls)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Suppress adds a fingerprint to the allowlist so it is never reported again.
func (s *Store) Suppress(fingerprint, reason string) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO suppressions(fingerprint,reason,ts) VALUES(?,?,?)`,
		strings.TrimSpace(fingerprint), reason, time.Now().UnixNano())
	return err
}

// Unsuppress removes a fingerprint from the allowlist.
func (s *Store) Unsuppress(fingerprint string) error {
	_, err := s.db.Exec(`DELETE FROM suppressions WHERE fingerprint=?`, fingerprint)
	return err
}
