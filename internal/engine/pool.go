// Package engine provides DarkObscura's concurrency primitives: a bounded
// worker pool implementing a fan-out/fan-in pattern, per-host token-bucket rate
// limiting, and a stateful session machine that carries cookies/CSRF tokens
// across requests during stateful fuzzing.
package engine

import (
	"context"
	"sync"
)

// Task is a unit of work processed by the pool. R is the result type.
type Task[T, R any] func(ctx context.Context, in T) (R, error)

// Result pairs an output with any error, preserving input for correlation.
type Result[T, R any] struct {
	In  T
	Out R
	Err error
}

// Pool runs tasks across a fixed number of workers (fan-out) and collects their
// results on a single channel (fan-in).
type Pool[T, R any] struct {
	workers int
	limiter *HostLimiter
}

// NewPool constructs a pool with the given worker count (min 1). limiter may be
// nil to disable rate limiting.
func NewPool[T, R any](workers int, limiter *HostLimiter) *Pool[T, R] {
	if workers < 1 {
		workers = 1
	}
	return &Pool[T, R]{workers: workers, limiter: limiter}
}

// Run fans inputs out across workers, applies task to each, and returns a
// channel of results that closes when all inputs are processed. keyFn optionally
// maps an input to a rate-limit key (host); pass nil to skip limiting.
func (p *Pool[T, R]) Run(ctx context.Context, inputs []T, task Task[T, R], keyFn func(T) string) <-chan Result[T, R] {
	in := make(chan T)
	out := make(chan Result[T, R])

	go func() {
		defer close(in)
		for _, item := range inputs {
			select {
			case in <- item:
			case <-ctx.Done():
				return
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(p.workers)
	for i := 0; i < p.workers; i++ {
		go func() {
			defer wg.Done()
			for item := range in {
				if p.limiter != nil && keyFn != nil {
					if err := p.limiter.Wait(ctx, keyFn(item)); err != nil {
						select {
						case out <- Result[T, R]{In: item, Err: err}:
						case <-ctx.Done():
						}
						continue
					}
				}
				res, err := task(ctx, item)
				select {
				case out <- Result[T, R]{In: item, Out: res, Err: err}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}
