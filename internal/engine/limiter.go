package engine

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

// HostLimiter applies an independent token bucket per host so aggressive fuzzing
// of one target never starves or overwhelms another.
type HostLimiter struct {
	rps   rate.Limit
	burst int

	mu      sync.Mutex
	buckets map[string]*rate.Limiter
}

// NewHostLimiter creates a limiter allowing rps requests/second per host with
// the given burst capacity.
func NewHostLimiter(rps float64, burst int) *HostLimiter {
	if burst < 1 {
		burst = 1
	}
	return &HostLimiter{
		rps:     rate.Limit(rps),
		burst:   burst,
		buckets: make(map[string]*rate.Limiter),
	}
}

// Wait blocks until a token is available for host or ctx is cancelled.
func (h *HostLimiter) Wait(ctx context.Context, host string) error {
	return h.bucket(host).Wait(ctx)
}

func (h *HostLimiter) bucket(host string) *rate.Limiter {
	h.mu.Lock()
	defer h.mu.Unlock()
	b, ok := h.buckets[host]
	if !ok {
		b = rate.NewLimiter(h.rps, h.burst)
		h.buckets[host] = b
	}
	return b
}
