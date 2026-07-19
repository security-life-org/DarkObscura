// Package ebpf provides optional kernel-level network visibility. On Linux with
// sufficient privileges (CAP_BPF/root) it can attach eBPF programs for
// zero-copy flow observation; on every other platform, or without privileges, it
// degrades gracefully to a no-op so the user-space proxy remains the source of
// truth. The build-tagged files select the right implementation.
package ebpf

import (
	"context"
	"time"
)

// KernelEvent is a flow event observed at the kernel boundary.
type KernelEvent struct {
	At       time.Time
	PID      uint32
	Comm     string
	SrcAddr  string
	DstAddr  string
	Bytes    uint64
	Protocol string // tcp | udp
}

// Observer attaches kernel hooks and streams KernelEvents. Implementations are
// selected at build time (see ebpf_linux.go / ebpf_stub.go).
type Observer interface {
	// Available reports whether kernel-level observation is usable in this
	// process (correct OS, kernel support, and privileges).
	Available() bool
	// Start begins observation, delivering events on the returned channel until
	// ctx is cancelled. Returns an error if attachment fails.
	Start(ctx context.Context) (<-chan KernelEvent, error)
	// Close detaches all hooks.
	Close() error
}
