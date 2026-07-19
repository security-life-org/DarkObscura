// Package waf tells the operator when the target is fighting back. DarkObscura can
// already fingerprint which WAF sits in front of a site, but that is useless
// during a scan if the tool silently eats block pages and reports "nothing
// found". waf classifies responses as clean / blocked / rate-limited / challenge,
// names the vendor, and — through Probe — actively determines whether the WAF
// blocks attack traffic specifically (baseline passes, malicious payload gets
// blocked). A Monitor aggregates verdicts across a scan so the UI can show a live
// "you are being blocked" signal and a block rate.
package waf

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/security-life-org/DarkObscura/internal/evasion"
)

// Kind classifies a response's blocking state.
type Kind string

const (
	Clean       Kind = "clean"
	Blocked     Kind = "waf-block"
	RateLimited Kind = "rate-limited"
	Challenge   Kind = "challenge"
)

// Verdict is the classification of a single response.
type Verdict struct {
	Kind    Kind
	Blocked bool   // true for Blocked/RateLimited/Challenge
	WAF     string // vendor name if identified ("" otherwise)
	Signal  string // what triggered the classification
}

// blockBody matches the tell-tale text of WAF block/challenge pages.
var blockBody = regexp.MustCompile(`(?i)` + strings.Join([]string{
	`attention required`, `cloudflare ray id`, `just a moment\.\.\.`, `checking your browser`,
	`access denied`, `request (?:blocked|rejected|unsuccessful)`, `you have been blocked`,
	`the requested url was rejected`, `web application firewall`, `malicious activity`,
	`incapsula incident`, `_incapsula_resource`, `sucuri website firewall`, `blocked by`,
	`security policy`, `not acceptable!?`, `forbidden by administrative rules`,
}, "|"))

// challengeBody matches JS/CAPTCHA interstitials specifically.
var challengeBody = regexp.MustCompile(`(?i)just a moment\.\.\.|checking your browser|hcaptcha|g-recaptcha|cf-challenge|turnstile`)

// Classify determines whether a response represents blocking. header may be nil
// (e.g. when only the body/status are available inside the scan pipeline).
func Classify(status int, header http.Header, body []byte) Verdict {
	vendor := ""
	if w := evasion.Fingerprint(header, body); w != nil {
		vendor = w.Name
	}

	// Rate limiting.
	if status == 429 || (header != nil && header.Get("Retry-After") != "") {
		return Verdict{Kind: RateLimited, Blocked: true, WAF: vendor, Signal: signalFor(status, "Retry-After / HTTP 429")}
	}
	// JS/CAPTCHA challenge.
	if challengeBody.Match(body) {
		return Verdict{Kind: Challenge, Blocked: true, WAF: vendor, Signal: "interstitial challenge page (JS/CAPTCHA)"}
	}
	// Hard blocks by status + WAF-ish body.
	blockStatus := status == 403 || status == 406 || status == 501 || status == 503 || status == 999
	bodyHit := blockBody.Match(body)
	if bodyHit || (blockStatus && vendor != "") {
		return Verdict{Kind: Blocked, Blocked: true, WAF: vendor, Signal: signalFor(status, bodySignal(bodyHit, vendor))}
	}
	// A bare 403 with no other signal is still likely a block during active fuzzing.
	if status == 403 {
		return Verdict{Kind: Blocked, Blocked: true, WAF: vendor, Signal: "HTTP 403 Forbidden"}
	}
	return Verdict{Kind: Clean, Blocked: false, WAF: vendor}
}

func bodySignal(hit bool, vendor string) string {
	if hit {
		return "block-page body signature"
	}
	if vendor != "" {
		return vendor + " block status"
	}
	return "block status"
}

func signalFor(status int, why string) string {
	return why + " (HTTP " + itoa(status) + ")"
}

// Probe actively determines whether the target blocks ATTACK traffic: it sends a
// benign request and a deliberately-malicious one, then compares. This
// distinguishes "no WAF", "WAF present but passive", and "WAF actively blocking
// our payloads" — the last explains empty scan results.
type ProbeResult struct {
	WAF          string
	Present      bool
	BlocksAttack bool
	Baseline     Verdict
	Attack       Verdict
	Evidence     []string
}

// attackValue is an obviously-malicious parameter value a WAF should flag. It is
// URL-encoded into the query so it survives transmission intact.
const attackValue = "1' OR '1'='1<script>alert(1)</script>../../../../etc/passwd"

// Probe runs the baseline-vs-attack comparison against target.
func Probe(ctx context.Context, client *http.Client, target string) (*ProbeResult, error) {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	base, err := fetch(ctx, client, target)
	if err != nil {
		return nil, err
	}
	attackURL := target
	if u, perr := url.Parse(target); perr == nil {
		q := u.Query()
		q.Set("dobscura", attackValue)
		u.RawQuery = q.Encode()
		attackURL = u.String()
	}
	atk, err := fetch(ctx, client, attackURL)
	if err != nil {
		return nil, err
	}
	r := &ProbeResult{
		WAF:          firstNonEmpty(atk.verdict.WAF, base.verdict.WAF),
		Baseline:     base.verdict,
		Attack:       atk.verdict,
		BlocksAttack: atk.verdict.Blocked && !base.verdict.Blocked,
	}
	r.Present = r.WAF != "" || r.BlocksAttack || base.verdict.Blocked
	switch {
	case base.verdict.Blocked:
		r.Evidence = append(r.Evidence, "the target blocks even a benign request ("+base.verdict.Signal+") — you are fully blocked")
	case r.BlocksAttack:
		r.Evidence = append(r.Evidence, "benign request passed but the attack payload was blocked ("+atk.verdict.Signal+") — the WAF actively filters attacks")
	case r.WAF != "":
		r.Evidence = append(r.Evidence, "WAF "+r.WAF+" is present but did not block the test payload")
	default:
		r.Evidence = append(r.Evidence, "no WAF detected and no blocking observed")
	}
	return r, nil
}

type fetchResult struct {
	verdict Verdict
}

func fetch(ctx context.Context, client *http.Client, url string) (fetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fetchResult{}, err
	}
	req.Header.Set("User-Agent", "DarkObscura")
	resp, err := client.Do(req)
	if err != nil {
		return fetchResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return fetchResult{verdict: Classify(resp.StatusCode, resp.Header, body)}, nil
}

// Monitor aggregates verdicts across a scan for a live block signal.
type Monitor struct {
	mu       sync.Mutex
	total    int
	blocked  int
	vendor   string
	notified bool
}

// Observe records one verdict and returns true the FIRST time a block is seen
// (so the caller can emit a single "you are being blocked" signal).
func (m *Monitor) Observe(v Verdict) (firstBlock bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.total++
	if v.WAF != "" {
		m.vendor = v.WAF
	}
	if v.Blocked {
		m.blocked++
		if !m.notified {
			m.notified = true
			return true
		}
	}
	return false
}

// Stats returns the running block statistics.
func (m *Monitor) Stats() (total, blocked int, rate float64, vendor string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := 0.0
	if m.total > 0 {
		r = float64(m.blocked) / float64(m.total)
	}
	return m.total, m.blocked, r, m.vendor
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [12]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}
