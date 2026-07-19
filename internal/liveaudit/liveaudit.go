// Package liveaudit turns DarkObscura from a batch scanner into an always-on
// auditor. It registers as a proxy.Interceptor, so every request that flows
// through the MITM proxy while the operator browses normally is canonicalized,
// deduplicated, and — if the endpoint is new — handed to the verification-gated
// fuzzer in the background. Only confirmed, never-before-seen findings surface
// (cross-scan dedup via internal/findings), so the operator sees a live stream of
// real bugs without ever launching a scan. Precision is inherited wholesale: the
// same exploit.Verifier and its zero-false-positive pipeline judge every probe.
package liveaudit

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/security-life-org/DarkObscura/internal/engine"
	"github.com/security-life-org/DarkObscura/internal/exploit"
	"github.com/security-life-org/DarkObscura/internal/findings"
)

// Auditor is a proxy interceptor that live-audits new endpoints. It is safe for
// concurrent use; the proxy invokes OnResponse from many goroutines.
type Auditor struct {
	canary  *exploit.CanaryServer
	store   *findings.Store // may be nil (dedup disabled)
	limiter *engine.HostLimiter

	// OnFinding is invoked once per confirmed, de-duplicated finding.
	OnFinding func(exploit.Finding)
	// InScope, if set, gates which hosts are audited (return true to allow).
	InScope func(host string) bool

	jobs chan string
	wg   sync.WaitGroup

	mu   sync.Mutex
	seen map[string]bool // canonical endpoint keys already queued
}

// Options configures an Auditor.
type Options struct {
	Canary   *exploit.CanaryServer
	Store    *findings.Store
	Workers  int             // concurrent audits (default 4)
	RPS      float64         // per-host request cap (default 8)
	OnFinding func(exploit.Finding)
	InScope   func(string) bool
}

// New builds an Auditor and starts its worker pool. Call Stop (or cancel ctx) to
// drain and shut down.
func New(ctx context.Context, opts Options) *Auditor {
	if opts.Workers <= 0 {
		opts.Workers = 4
	}
	if opts.RPS <= 0 {
		opts.RPS = 8
	}
	a := &Auditor{
		canary:    opts.Canary,
		store:     opts.Store,
		limiter:   engine.NewHostLimiter(opts.RPS, int(opts.RPS)+1),
		OnFinding: opts.OnFinding,
		InScope:   opts.InScope,
		jobs:      make(chan string, 256),
		seen:      make(map[string]bool),
	}
	for i := 0; i < opts.Workers; i++ {
		a.wg.Add(1)
		go a.worker(ctx)
	}
	return a
}

// OnRequest satisfies proxy.Interceptor; live-audit never mutates requests.
func (a *Auditor) OnRequest(*http.Request) *http.Response { return nil }

// OnResponse satisfies proxy.Interceptor. It enqueues newly-seen, parameterized
// endpoints for background auditing.
func (a *Auditor) OnResponse(r *http.Request, _ *http.Response) {
	u := reconstruct(r)
	if u == nil || u.RawQuery == "" {
		return // only audit endpoints that actually take parameters
	}
	if a.InScope != nil && !a.InScope(u.Hostname()) {
		return
	}
	key := canonical(u)
	a.mu.Lock()
	if a.seen[key] {
		a.mu.Unlock()
		return
	}
	a.seen[key] = true
	a.mu.Unlock()

	select {
	case a.jobs <- u.String():
	default: // queue full: drop rather than block the proxy hot path
	}
}

func (a *Auditor) worker(ctx context.Context) {
	defer a.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case target, ok := <-a.jobs:
			if !ok {
				return
			}
			a.audit(ctx, target)
		}
	}
}

func (a *Auditor) audit(ctx context.Context, target string) {
	if u, err := url.Parse(target); err == nil {
		_ = a.limiter.Wait(ctx, u.Hostname())
	}
	sess, err := engine.NewSession()
	if err != nil {
		return
	}
	fz := exploit.NewFuzzer(sess, exploit.NewVerifier(a.canary), a.canary)
	fz.FastMode = true // keep the live pipeline responsive; time-based runs in explicit scans
	found, err := fz.FuzzURL(ctx, target)
	if err != nil {
		return
	}
	fresh := a.dedup(found)
	for _, f := range fresh {
		if a.OnFinding != nil {
			a.OnFinding(f)
		}
	}
}

// dedup filters findings through the cross-scan store (if configured), returning
// only the ones never seen before.
func (a *Auditor) dedup(found []exploit.Finding) []exploit.Finding {
	if a.store == nil {
		return found
	}
	var recs []findings.Record
	for _, f := range found {
		recs = append(recs, findings.Record{
			Target: f.Target, Param: f.Param, Class: f.Class,
			Severity: string(f.Severity), Payload: f.Payload, VerifiedVia: f.VerifiedVia,
		})
	}
	freshRecs, err := a.store.Upsert(recs)
	if err != nil {
		return found
	}
	freshKeys := make(map[string]bool, len(freshRecs))
	for _, r := range freshRecs {
		freshKeys[findings.Fingerprint(r.Target, r.Param, r.Class)] = true
	}
	var out []exploit.Finding
	for _, f := range found {
		if freshKeys[findings.Fingerprint(f.Target, f.Param, f.Class)] {
			out = append(out, f)
		}
	}
	return out
}

// Stop drains the queue and waits for workers to finish. Cancel the ctx passed
// to New first (or rely on it) to unblock in-flight audits.
func (a *Auditor) Stop() {
	close(a.jobs)
	a.wg.Wait()
}

// reconstruct rebuilds an absolute URL from a proxied request. The MITM handler
// sets scheme/host on the decrypted request; plain proxying carries an absolute
// URL. Falls back to r.Host when URL.Host is empty.
func reconstruct(r *http.Request) *url.URL {
	if r.URL == nil {
		return nil
	}
	u := *r.URL
	if u.Host == "" {
		u.Host = r.Host
	}
	if u.Scheme == "" {
		if r.TLS != nil {
			u.Scheme = "https"
		} else {
			u.Scheme = "http"
		}
	}
	if u.Host == "" {
		return nil
	}
	return &u
}

// canonical keys an endpoint by host+path+sorted-param-NAMES (values ignored), so
// the same endpoint hit with different values is audited once.
func canonical(u *url.URL) string {
	names := make([]string, 0, len(u.Query()))
	for k := range u.Query() {
		names = append(names, k)
	}
	sort.Strings(names)
	return u.Hostname() + u.Path + "?" + strings.Join(names, "&")
}
