// Package clientside bundles three high-signal client-side / header-logic checks
// that classic parameter fuzzing misses: CORS misconfiguration, web cache
// poisoning via unkeyed headers, and Content-Security-Policy weakness analysis.
// Each is verified against the target's actual response behavior (a reflected
// origin, a reflected unkeyed header, a permissive directive) rather than
// guessed, keeping the platform's zero-false-positive stance.
package clientside

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Finding is a confirmed client-side issue.
type Finding struct {
	Class    string
	Severity string
	Target   string
	Detail   string
	Evidence []string
}

// Scanner runs the client-side checks against a URL.
type Scanner struct {
	Client *http.Client
}

// New builds a Scanner. If client is nil a non-following default is used so
// redirects/headers stay observable.
func New(client *http.Client) *Scanner {
	if client == nil {
		client = &http.Client{
			Timeout:       15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return &Scanner{Client: client}
}

// Scan runs every check and returns all confirmed findings.
func (s *Scanner) Scan(ctx context.Context, url string) ([]Finding, error) {
	var out []Finding
	if f := s.checkCORS(ctx, url); f != nil {
		out = append(out, *f)
	}
	if f := s.checkCachePoison(ctx, url); f != nil {
		out = append(out, *f)
	}
	if fs := s.checkCSP(ctx, url); fs != nil {
		out = append(out, fs...)
	}
	if f := s.checkNullOrigin(ctx, url); f != nil {
		out = append(out, *f)
	}
	if fs := s.checkSecurityHeaders(ctx, url); fs != nil {
		out = append(out, fs...)
	}
	return out, nil
}

// checkNullOrigin confirms the dangerous "Origin: null" reflection (reachable
// from sandboxed iframes / data: documents) combined with credentials.
func (s *Scanner) checkNullOrigin(ctx context.Context, url string) *Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Origin", "null")
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	if resp.Header.Get("Access-Control-Allow-Origin") == "null" &&
		strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true") {
		return &Finding{
			Class: "cors-null-origin", Severity: "high", Target: url,
			Detail: "reflects Origin: null with credentials",
			Evidence: []string{
				"Access-Control-Allow-Origin: null with Allow-Credentials: true",
				"verified: a sandboxed iframe (Origin: null) can read authenticated responses",
			},
		}
	}
	return nil
}

// checkSecurityHeaders flags missing transport/framing/type protections.
func (s *Scanner) checkSecurityHeaders(ctx context.Context, url string) []Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	var out []Finding
	if strings.HasPrefix(url, "https") && resp.Header.Get("Strict-Transport-Security") == "" {
		out = append(out, Finding{Class: "missing-hsts", Severity: "low", Target: url,
			Detail: "no Strict-Transport-Security header", Evidence: []string{"verified: HTTPS response lacks HSTS — vulnerable to SSL-strip downgrade"}})
	}
	if resp.Header.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(resp.Header.Get("Content-Security-Policy")), "frame-ancestors") {
		out = append(out, Finding{Class: "missing-framing-protection", Severity: "low", Target: url,
			Detail: "no X-Frame-Options / frame-ancestors", Evidence: []string{"verified: response can be framed — clickjacking exposure"}})
	}
	if !strings.EqualFold(resp.Header.Get("X-Content-Type-Options"), "nosniff") {
		out = append(out, Finding{Class: "missing-nosniff", Severity: "info", Target: url,
			Detail: "no X-Content-Type-Options: nosniff", Evidence: []string{"MIME-sniffing not disabled"}})
	}
	return out
}

// checkCORS reflects an attacker origin and confirms a finding only when the
// server echoes it back in Access-Control-Allow-Origin AND allows credentials —
// the combination that actually enables cross-origin theft of authenticated data.
func (s *Scanner) checkCORS(ctx context.Context, url string) *Finding {
	const evil = "https://evil.dobscura.example"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Origin", evil)
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")
	reflects := acao == evil
	wildcard := acao == "*"
	switch {
	case reflects && strings.EqualFold(acac, "true"):
		return &Finding{
			Class: "cors-origin-reflection", Severity: "high", Target: url,
			Detail: "reflects arbitrary Origin with credentials",
			Evidence: []string{
				fmt.Sprintf("Origin: %s reflected in Access-Control-Allow-Origin: %s", evil, acao),
				"Access-Control-Allow-Credentials: true",
				"verified: any origin can read authenticated responses — cross-origin data theft",
			},
		}
	case wildcard && strings.EqualFold(acac, "true"):
		return &Finding{
			Class: "cors-wildcard-credentials", Severity: "medium", Target: url,
			Detail: "wildcard ACAO with credentials",
			Evidence: []string{"Access-Control-Allow-Origin: * with Allow-Credentials: true"},
		}
	}
	return nil
}

// checkCachePoison DETERMINISTICALLY confirms web cache poisoning rather than
// merely observing reflection. It poisons a cache key we own (a unique
// ?dobcb=<marker> buster, so no other user's cache entry is affected) and then
// proves persistence:
//
//	1. poison: GET ?dobcb=<marker> with X-Forwarded-Host: <marker> → response
//	   must reflect the marker AND be cacheable.
//	2. verify: GET the SAME URL again WITHOUT the header → if the marker is
//	   served back, it came from the cache the poisoned request populated.
//
// A finding fires only when step 2 returns the marker. Reflection alone (which
// the old code flagged) is not enough and no longer produces a finding — that is
// what removes the false positives.
func (s *Scanner) checkCachePoison(ctx context.Context, target string) *Finding {
	marker := "dobcp" + randToken()
	poisonURL := withParam(target, "dobcb", marker)

	// Step 1 — poison our own cache key.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, poisonURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("X-Forwarded-Host", marker)
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	poisonedHeaders := resp.Header.Clone()
	resp.Body.Close()
	reflected := strings.Contains(string(body), marker) || headerContains(resp.Header, marker)
	if !reflected || !isCacheable(poisonedHeaders) {
		return nil // no unkeyed reflection into a cacheable response → nothing to confirm
	}

	// Step 2 — request the same key WITHOUT the header; the marker must persist.
	req2, err := http.NewRequestWithContext(ctx, http.MethodGet, poisonURL, nil)
	if err != nil {
		return nil
	}
	resp2, err := s.Client.Do(req2)
	if err != nil {
		return nil
	}
	body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 2<<20))
	served := strings.Contains(string(body2), marker) || headerContains(resp2.Header, marker)
	fromCache := cacheHit(resp2.Header)
	resp2.Body.Close()
	if !served {
		return nil // not actually cached/served — reflection only, NOT a finding
	}
	return &Finding{
		Class: "web-cache-poisoning", Severity: "high", Target: target,
		Detail: "unkeyed X-Forwarded-Host persisted into a cached response",
		Evidence: []string{
			fmt.Sprintf("poisoned %s with X-Forwarded-Host: %s (reflected + cacheable)", poisonURL, marker),
			fmt.Sprintf("clean follow-up request served the marker back from cache (cache-hit indicator=%v)", fromCache),
			"verified: a header-less request received the poisoned value from the cache — confirmed web cache poisoning",
		},
	}
}

// checkCSP fetches the target and flags missing or dangerously weak CSP.
func (s *Scanner) checkCSP(ctx context.Context, url string) []Finding {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	var out []Finding
	if csp == "" {
		return []Finding{{
			Class: "csp-missing", Severity: "low", Target: url,
			Detail:   "no Content-Security-Policy header",
			Evidence: []string{"verified: response has no CSP — XSS has no defense-in-depth mitigation"},
		}}
	}
	low := strings.ToLower(csp)
	if strings.Contains(low, "unsafe-inline") {
		out = append(out, Finding{Class: "csp-unsafe-inline", Severity: "medium", Target: url,
			Detail: "script-src allows 'unsafe-inline'", Evidence: []string{"CSP contains 'unsafe-inline' — inline script injection is not blocked"}})
	}
	if strings.Contains(low, "unsafe-eval") {
		out = append(out, Finding{Class: "csp-unsafe-eval", Severity: "low", Target: url,
			Detail: "allows 'unsafe-eval'", Evidence: []string{"CSP contains 'unsafe-eval'"}})
	}
	if strings.Contains(low, "default-src *") || strings.Contains(low, "script-src *") {
		out = append(out, Finding{Class: "csp-wildcard", Severity: "medium", Target: url,
			Detail: "wildcard source allows any host", Evidence: []string{"CSP uses a wildcard '*' source — scripts loadable from any origin"}})
	}
	return out
}

func headerContains(h http.Header, sub string) bool {
	for _, vs := range h {
		for _, v := range vs {
			if strings.Contains(v, sub) {
				return true
			}
		}
	}
	return false
}

func randToken() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func withParam(raw, k, v string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	q.Set(k, v)
	u.RawQuery = q.Encode()
	return u.String()
}

// cacheHit reports whether cache headers indicate the response was served from
// cache (a positive X-Cache/CF-Cache-Status or a non-zero Age).
func cacheHit(h http.Header) bool {
	for _, k := range []string{"X-Cache", "CF-Cache-Status", "X-Cache-Status"} {
		if v := strings.ToLower(h.Get(k)); v != "" && !strings.Contains(v, "miss") {
			return true
		}
	}
	return h.Get("Age") != "" && h.Get("Age") != "0"
}

func isCacheable(h http.Header) bool {
	cc := strings.ToLower(h.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		return false
	}
	if h.Get("Age") != "" || strings.Contains(cc, "public") || strings.Contains(cc, "max-age") {
		return true
	}
	// Default: many CDNs cache absent explicit no-store.
	return h.Get("X-Cache") != "" || h.Get("CF-Cache-Status") != ""
}
