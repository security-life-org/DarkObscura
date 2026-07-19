// Package secrets scans response bodies and JavaScript for leaked credentials.
// It goes beyond spotting an exposed .env file: it applies typed regex detectors
// for common credential formats (cloud keys, payment tokens, JWTs, private keys)
// and a Shannon-entropy gate for generic high-entropy strings, so a hard-coded
// API key in a JS bundle is caught even when its variable name gives nothing
// away. Matches are redacted before they are surfaced so the tool never widens
// the exposure it is reporting.
package secrets

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// Match is one detected secret.
type Match struct {
	Type     string  // e.g. "AWS Access Key ID"
	Severity string  // "critical" | "high" | "medium"
	Redacted string  // safe-to-display, partially masked
	Entropy  float64 // Shannon entropy of the raw match (0 if rule-based)
	Context  string  // short surrounding snippet (redacted)
}

type detector struct {
	typ      string
	severity string
	re       *regexp.Regexp
}

var detectors = []detector{
	{"AWS Access Key ID", "high", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"AWS Secret Access Key", "critical", regexp.MustCompile(`(?i)aws.{0,20}?['"][0-9a-zA-Z/+]{40}['"]`)},
	{"Google API Key", "high", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{"GCP Service Account", "critical", regexp.MustCompile(`"type":\s*"service_account"`)},
	{"Stripe Secret Key", "critical", regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{24,}\b`)},
	{"Stripe Restricted Key", "high", regexp.MustCompile(`\brk_live_[0-9a-zA-Z]{24,}\b`)},
	{"GitHub Token", "critical", regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{36,}\b`)},
	{"Slack Token", "high", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z\-]{10,}\b`)},
	{"Private Key Block", "critical", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)},
	{"JWT", "medium", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`)},
	{"Generic API Key Assignment", "medium", regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|passwd|password)['"]?\s*[:=]\s*['"][0-9a-zA-Z\-_/+.]{16,}['"]`)},
	{"Bearer Token", "medium", regexp.MustCompile(`(?i)bearer\s+[0-9a-zA-Z\-_.=]{20,}`)},
	// round-2: doubled detector set.
	{"Azure Storage Key", "critical", regexp.MustCompile(`(?i)AccountKey=[0-9a-zA-Z+/]{80,}==`)},
	{"Azure Connection String", "critical", regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https;AccountName=`)},
	{"Twilio Account SID", "high", regexp.MustCompile(`\bAC[0-9a-fA-F]{32}\b`)},
	{"Twilio Auth Token", "critical", regexp.MustCompile(`(?i)twilio.{0,20}?\b[0-9a-f]{32}\b`)},
	{"SendGrid API Key", "critical", regexp.MustCompile(`\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b`)},
	{"Mailgun API Key", "high", regexp.MustCompile(`\bkey-[0-9a-zA-Z]{32}\b`)},
	{"npm Token", "high", regexp.MustCompile(`\bnpm_[0-9A-Za-z]{36}\b`)},
	{"PyPI Token", "high", regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[0-9A-Za-z_\-]{50,}\b`)},
	{"Heroku API Key", "high", regexp.MustCompile(`(?i)heroku.{0,20}?\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)},
	{"DigitalOcean Token", "high", regexp.MustCompile(`\bdop_v1_[0-9a-f]{64}\b`)},
	{"Database Connection URL", "critical", regexp.MustCompile(`(?i)(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@]+:[^\s:@]+@[^\s/]+`)},
	{"JDBC Credentials", "high", regexp.MustCompile(`(?i)jdbc:[a-z]+://[^\s]*password=[^\s&"']+`)},
	{"Firebase Database URL", "medium", regexp.MustCompile(`https://[a-z0-9\-]+\.firebaseio\.com`)},
	{"Facebook Access Token", "high", regexp.MustCompile(`\bEAACEdEose0cBA[0-9A-Za-z]+\b`)},
	{"Discord Bot Token", "high", regexp.MustCompile(`\b[MNO][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b`)},
	{"Telegram Bot Token", "high", regexp.MustCompile(`\b\d{8,10}:[A-Za-z0-9_\-]{35}\b`)},
	{"Basic Auth in URL", "high", regexp.MustCompile(`https?://[^\s:@/]+:[^\s:@/]+@[^\s/]+`)},
}

// Scan searches data for secrets and returns deduplicated, redacted matches.
func Scan(data []byte) []Match {
	s := string(data)
	seen := map[string]bool{}
	var out []Match
	for _, d := range detectors {
		for _, loc := range d.re.FindAllStringIndex(s, -1) {
			raw := s[loc[0]:loc[1]]
			key := d.typ + "|" + raw
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Match{
				Type:     d.typ,
				Severity: d.severity,
				Redacted: redact(raw),
				Entropy:  shannon(raw),
				Context:  snippet(s, loc[0], loc[1]),
			})
		}
	}
	out = append(out, entropyScan(s, seen)...)
	return out
}

// entropyScan catches high-entropy tokens the typed detectors miss (e.g. custom
// key formats). It only reports long strings whose entropy exceeds a threshold,
// which keeps normal text out.
func entropyScan(s string, seen map[string]bool) []Match {
	var out []Match
	tokenRe := regexp.MustCompile(`[A-Za-z0-9+/_\-]{32,64}`)
	for _, tok := range tokenRe.FindAllString(s, -1) {
		if seen["entropy|"+tok] {
			continue
		}
		e := shannon(tok)
		if e < 4.0 { // below ~4 bits/char is unlikely to be a random secret
			continue
		}
		seen["entropy|"+tok] = true
		out = append(out, Match{
			Type: "High-Entropy String", Severity: "medium",
			Redacted: redact(tok), Entropy: e,
		})
	}
	return out
}

// shannon returns the Shannon entropy (bits per character) of s.
func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// redact masks the middle of a secret, keeping only enough to identify it.
func redact(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

// snippet returns a short redacted context window around a match.
func snippet(s string, start, end int) string {
	const pad = 16
	from := start - pad
	if from < 0 {
		from = 0
	}
	to := end + pad
	if to > len(s) {
		to = len(s)
	}
	ctx := s[from:start] + redact(s[start:end]) + s[end:to]
	return fmt.Sprintf("…%s…", strings.ReplaceAll(ctx, "\n", " "))
}
