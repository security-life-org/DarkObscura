// Package passive analyzes captured HTTP responses for security issues without
// sending any additional requests. It surfaces misconfigurations that active
// fuzzing misses: missing security headers, insecure cookies, permissive CORS,
// version/tech disclosure, verbose error leakage, and secrets exposed in bodies.
package passive

import (
	"net/http"
	"regexp"
	"strings"
)

// Issue is a passively-detected finding.
type Issue struct {
	Class    string `json:"class"`
	Severity string `json:"severity"` // critical | high | medium | low | info
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Evidence string `json:"evidence"`
}

// Audit runs all passive checks against one response and returns any issues.
// scheme is "http" or "https" (affects HSTS relevance).
func Audit(scheme string, status int, header http.Header, body []byte) []Issue {
	var issues []Issue
	issues = append(issues, checkSecurityHeaders(scheme, header)...)
	issues = append(issues, checkCookies(header)...)
	issues = append(issues, checkCORS(header)...)
	issues = append(issues, checkDisclosure(header, body)...)
	issues = append(issues, checkSecrets(body)...)
	return issues
}

// checkSecurityHeaders flags missing hardening headers.
func checkSecurityHeaders(scheme string, h http.Header) []Issue {
	var out []Issue
	miss := func(name, class, sev, title, detail string) {
		if h.Get(name) == "" {
			out = append(out, Issue{Class: class, Severity: sev, Title: title, Detail: detail,
				Evidence: "response header '" + name + "' absent"})
		}
	}
	miss("Content-Security-Policy", "missing-csp", "medium", "No Content-Security-Policy",
		"Without CSP the page has no defense-in-depth against XSS/data injection.")
	miss("X-Content-Type-Options", "missing-nosniff", "low", "No X-Content-Type-Options",
		"Missing 'nosniff' allows MIME-sniffing content-type confusion attacks.")
	if h.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(h.Get("Content-Security-Policy")), "frame-ancestors") {
		out = append(out, Issue{Class: "clickjacking", Severity: "medium", Title: "Framing not restricted",
			Detail: "No X-Frame-Options or CSP frame-ancestors — page can be framed (clickjacking).",
			Evidence: "no X-Frame-Options and no CSP frame-ancestors"})
	}
	miss("Referrer-Policy", "missing-referrer-policy", "low", "No Referrer-Policy",
		"Referrer may leak sensitive URLs to third parties.")
	if scheme == "https" && h.Get("Strict-Transport-Security") == "" {
		out = append(out, Issue{Class: "missing-hsts", Severity: "medium", Title: "No HSTS",
			Detail: "HTTPS response lacks Strict-Transport-Security — vulnerable to SSL-strip/downgrade.",
			Evidence: "no Strict-Transport-Security on an HTTPS response"})
	}
	return out
}

// checkCookies flags Set-Cookie values missing protective attributes.
func checkCookies(h http.Header) []Issue {
	var out []Issue
	for _, c := range h.Values("Set-Cookie") {
		lc := strings.ToLower(c)
		name := c
		if i := strings.IndexByte(c, '='); i > 0 {
			name = c[:i]
		}
		var missing []string
		if !strings.Contains(lc, "httponly") {
			missing = append(missing, "HttpOnly")
		}
		if !strings.Contains(lc, "secure") {
			missing = append(missing, "Secure")
		}
		if !strings.Contains(lc, "samesite") {
			missing = append(missing, "SameSite")
		}
		if len(missing) > 0 {
			sev := "low"
			if contains(missing, "HttpOnly") {
				sev = "medium" // JS-readable session cookies are higher risk
			}
			out = append(out, Issue{Class: "insecure-cookie", Severity: sev,
				Title: "Cookie missing " + strings.Join(missing, "/"),
				Detail: "Cookie '" + name + "' is set without " + strings.Join(missing, ", ") + ".",
				Evidence: truncate(c, 120)})
		}
	}
	return out
}

// checkCORS flags dangerously permissive CORS response headers.
func checkCORS(h http.Header) []Issue {
	acao := h.Get("Access-Control-Allow-Origin")
	acac := strings.ToLower(h.Get("Access-Control-Allow-Credentials"))
	if acao == "*" && acac == "true" {
		return []Issue{{Class: "cors-misconfig", Severity: "high", Title: "Wildcard CORS with credentials",
			Detail: "Access-Control-Allow-Origin '*' combined with credentials lets any origin read authenticated responses.",
			Evidence: "ACAO: * / ACAC: true"}}
	}
	if acao == "*" {
		return []Issue{{Class: "cors-open", Severity: "low", Title: "Wildcard CORS",
			Detail: "Access-Control-Allow-Origin '*' exposes responses to any origin.", Evidence: "ACAO: *"}}
	}
	return nil
}

var (
	stackRe  = regexp.MustCompile(`(?i)(stack trace|traceback \(most recent call last\)|at [\w.$]+\([\w.]+\.java:\d+\)|\.php on line \d+|Warning: |Fatal error: |Exception in thread)`)
	verboseRe = regexp.MustCompile(`(?i)(sql syntax|ORA-\d{5}|SQLSTATE\[|PostgreSQL.*ERROR|mysql_fetch|Microsoft OLE DB)`)
)

// checkDisclosure flags version/tech disclosure and verbose error leakage.
func checkDisclosure(h http.Header, body []byte) []Issue {
	var out []Issue
	for _, hdr := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"} {
		if v := h.Get(hdr); v != "" && strings.ContainsAny(v, "0123456789") {
			out = append(out, Issue{Class: "version-disclosure", Severity: "info",
				Title: "Technology/version disclosed", Detail: "Header '" + hdr + "' reveals server technology and version.",
				Evidence: hdr + ": " + v})
		}
	}
	if m := stackRe.Find(body); m != nil {
		out = append(out, Issue{Class: "verbose-error", Severity: "medium", Title: "Stack trace / debug output leaked",
			Detail: "The response body contains a stack trace or framework debug output.",
			Evidence: truncate(string(m), 120)})
	}
	if m := verboseRe.Find(body); m != nil {
		out = append(out, Issue{Class: "db-error-leak", Severity: "medium", Title: "Database error leaked",
			Detail: "A database error string is exposed, aiding injection attacks.",
			Evidence: truncate(string(m), 120)})
	}
	return out
}

// secretPatterns match high-confidence credentials/keys in response bodies.
var secretPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"AWS access key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"Google API key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"Slack token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,48}`)},
	{"private key", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----`)},
	{"generic secret assignment", regexp.MustCompile(`(?i)(api[_-]?key|secret|password|token)"?\s*[:=]\s*"[A-Za-z0-9\-_]{16,}"`)},
	{"JWT", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
}

// checkSecrets flags credentials/keys exposed in the response body.
func checkSecrets(body []byte) []Issue {
	var out []Issue
	for _, p := range secretPatterns {
		if m := p.re.Find(body); m != nil {
			out = append(out, Issue{Class: "exposed-secret", Severity: "high",
				Title: p.name + " exposed in response", Detail: "A " + p.name + " appears in the response body.",
				Evidence: redact(string(m))})
		}
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// redact masks the middle of a secret so evidence is shown without full leakage.
func redact(s string) string {
	if len(s) <= 10 {
		return s[:2] + "****"
	}
	return s[:6] + "…" + s[len(s)-4:]
}
