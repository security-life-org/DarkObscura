// Package netutil holds small reusable network and identity helpers.
package netutil

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"time"
)

var enc = base32.NewEncoding("0123456789abcdefghijklmnopqrstuv").WithPadding(base32.NoPadding)

// NewID returns a lexicographically-sortable, time-prefixed unique identifier
// (a ULID-style value): 6 bytes of millisecond timestamp + 10 random bytes.
func NewID() string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(time.Now().UnixMilli())<<16)
	_, _ = rand.Read(b[6:])
	return enc.EncodeToString(b[:])
}
