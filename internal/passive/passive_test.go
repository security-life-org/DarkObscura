package passive

import (
	"net/http"
	"testing"
)

func has(issues []Issue, class string) bool {
	for _, i := range issues {
		if i.Class == class {
			return true
		}
	}
	return false
}

func TestMissingSecurityHeaders(t *testing.T) {
	h := http.Header{}
	issues := Audit("https", 200, h, []byte("ok"))
	for _, want := range []string{"missing-csp", "missing-nosniff", "clickjacking", "missing-hsts"} {
		if !has(issues, want) {
			t.Errorf("expected %s issue on a bare HTTPS response", want)
		}
	}
}

func TestSecureResponseIsClean(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Strict-Transport-Security", "max-age=63072000")
	issues := Audit("https", 200, h, []byte("ok"))
	for _, bad := range []string{"missing-csp", "missing-nosniff", "clickjacking", "missing-hsts", "missing-referrer-policy"} {
		if has(issues, bad) {
			t.Errorf("hardened response should not flag %s", bad)
		}
	}
}

func TestInsecureCookie(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "session=abc123; Path=/")
	issues := Audit("https", 200, h, nil)
	if !has(issues, "insecure-cookie") {
		t.Fatal("expected insecure-cookie for a cookie without HttpOnly/Secure/SameSite")
	}
}

func TestSecureCookieClean(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict")
	issues := Audit("https", 200, h, nil)
	if has(issues, "insecure-cookie") {
		t.Fatal("fully-flagged cookie must not be reported")
	}
}

func TestCORSWildcardWithCredentials(t *testing.T) {
	h := http.Header{}
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Credentials", "true")
	issues := Audit("https", 200, h, nil)
	if !has(issues, "cors-misconfig") {
		t.Fatal("expected cors-misconfig for wildcard+credentials")
	}
}

func TestSecretDetection(t *testing.T) {
	body := []byte(`{"config":{"aws":"AKIAIOSFODNN7EXAMPLE","note":"do not leak"}}`)
	issues := Audit("https", 200, http.Header{}, body)
	if !has(issues, "exposed-secret") {
		t.Fatal("expected AWS key detection")
	}
	for _, i := range issues {
		if i.Class == "exposed-secret" && i.Evidence == "AKIAIOSFODNN7EXAMPLE" {
			t.Fatal("secret evidence must be redacted, not shown in full")
		}
	}
}

func TestVerboseError(t *testing.T) {
	body := []byte("Warning: mysql_fetch_array() expects parameter 1 ... You have an error in your SQL syntax")
	issues := Audit("http", 500, http.Header{}, body)
	if !has(issues, "db-error-leak") && !has(issues, "verbose-error") {
		t.Fatal("expected verbose-error / db-error-leak detection")
	}
}
