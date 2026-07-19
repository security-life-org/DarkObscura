//go:build !linux

package ebpf

import "context"

// stubObserver is used on non-Linux platforms; kernel observation is unavailable
// and the proxy remains the sole flow source.
type stubObserver struct{}

// NewObserver returns a no-op Observer on non-Linux platforms.
func NewObserver() Observer { return stubObserver{} }

func (stubObserver) Available() bool { return false }

func (stubObserver) Start(ctx context.Context) (<-chan KernelEvent, error) {
	ch := make(chan KernelEvent)
	close(ch)
	return ch, nil
}

func (stubObserver) Close() error { return nil }
