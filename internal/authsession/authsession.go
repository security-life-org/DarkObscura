// Package authsession adds authenticated scanning to DarkObscura. Most high-value
// bugs (IDOR, business logic, privileged actions) live behind a login, but a
// scanner that logs in once and then silently loses its session reports a clean
// scan of the login wall. authsession performs the login flow (form POST or
// bearer/header token), detects when the session has expired by a caller-supplied
// signature in the response, and transparently re-authenticates before retrying.
// It produces a *engine.Session so the rest of the pipeline (fuzzer, verifier)
// runs authenticated with no further changes.
package authsession

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/security-life-org/DarkObscura/internal/engine"
)

// Method selects how authentication is performed.
type Method int

const (
	// FormLogin POSTs credentials to a login URL; the resulting cookies are the
	// session (stored in the session's cookie jar).
	FormLogin Method = iota
	// BearerToken sets a static Authorization header on every request.
	BearerToken
	// HeaderToken sets an arbitrary header (e.g. X-API-Key) on every request.
	HeaderToken
)

// Config describes how to authenticate and how to recognize a dead session.
type Config struct {
	Method Method

	// FormLogin fields.
	LoginURL   string
	FormFields map[string]string // e.g. {"username":"u","password":"p"}

	// BearerToken / HeaderToken fields.
	HeaderName  string // for HeaderToken; ignored for BearerToken (uses Authorization)
	HeaderValue string // token value (BearerToken prepends "Bearer ")

	// ExpirySignature is a substring whose presence in a response body/redirect
	// means the session is no longer valid (e.g. "Please log in", "/login").
	// Empty disables auto-reauth detection.
	ExpirySignature string
}

// Authenticator owns a live authenticated session and knows how to rebuild it.
type Authenticator struct {
	cfg     Config
	mu      sync.Mutex
	session *engine.Session
}

// New logs in and returns a ready Authenticator holding a live session.
func New(ctx context.Context, cfg Config) (*Authenticator, error) {
	a := &Authenticator{cfg: cfg}
	if err := a.login(ctx); err != nil {
		return nil, err
	}
	return a, nil
}

// Session returns the current authenticated *engine.Session.
func (a *Authenticator) Session() *engine.Session {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.session
}

// login (re)establishes the session according to the configured method.
func (a *Authenticator) login(ctx context.Context) error {
	sess, err := engine.NewSession()
	if err != nil {
		return err
	}
	// Header-based auth is applied per-request via a RoundTripper wrapper.
	switch a.cfg.Method {
	case BearerToken:
		sess.Client.Transport = headerRT{name: "Authorization", value: "Bearer " + a.cfg.HeaderValue, base: transport(sess)}
	case HeaderToken:
		name := a.cfg.HeaderName
		if name == "" {
			name = "X-API-Key"
		}
		sess.Client.Transport = headerRT{name: name, value: a.cfg.HeaderValue, base: transport(sess)}
	case FormLogin:
		if err := formLogin(ctx, sess, a.cfg); err != nil {
			return err
		}
	}
	a.mu.Lock()
	a.session = sess
	a.mu.Unlock()
	return nil
}

func transport(sess *engine.Session) http.RoundTripper {
	if sess.Client.Transport != nil {
		return sess.Client.Transport
	}
	return http.DefaultTransport
}

func formLogin(ctx context.Context, sess *engine.Session, cfg Config) error {
	form := url.Values{}
	for k, v := range cfg.FormFields {
		form.Set(k, v)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.LoginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := sess.Client.Do(req)
	if err != nil {
		return fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	sess.Observe(body) // pick up any CSRF token for subsequent stateful requests
	if resp.StatusCode >= 400 {
		return fmt.Errorf("login failed: HTTP %d", resp.StatusCode)
	}
	return nil
}

// Do issues req through the authenticated session and, if the response looks
// like an expired-session page, re-authenticates once and retries. The retry
// buffers the body so it can be replayed.
func (a *Authenticator) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}
	rebuild := func() *http.Request {
		r := req.Clone(ctx)
		if bodyBytes != nil {
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		return r
	}

	resp, err := a.Session().Client.Do(rebuild())
	if err != nil {
		return nil, err
	}
	if a.cfg.ExpirySignature == "" {
		return resp, nil
	}
	// Peek the body to check for an expiry signature.
	peek, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if bytes.Contains(peek, []byte(a.cfg.ExpirySignature)) {
		if err := a.login(ctx); err != nil {
			return nil, fmt.Errorf("re-auth: %w", err)
		}
		return a.Session().Client.Do(rebuild())
	}
	resp.Body = io.NopCloser(bytes.NewReader(peek))
	return resp, nil
}

// KeepAlive re-authenticates on a fixed interval until ctx is cancelled. Useful
// for long deep-scans where the session TTL is shorter than the scan.
func (a *Authenticator) KeepAlive(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = a.login(ctx)
		}
	}
}

// headerRT injects a fixed header on every outbound request.
type headerRT struct {
	name, value string
	base        http.RoundTripper
}

func (h headerRT) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set(h.name, h.value)
	return h.base.RoundTrip(r)
}
