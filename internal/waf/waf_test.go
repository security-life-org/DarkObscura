package waf

import (
	"net/http"
	"testing"
)

func TestClassify_CloudflareBlock(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "cloudflare")
	h.Set("CF-RAY", "abc123")
	body := []byte("<html><title>Attention Required! | Cloudflare</title>Access denied</html>")
	v := Classify(403, h, body)
	if !v.Blocked || v.Kind != Blocked {
		t.Fatalf("expected blocked; got %+v", v)
	}
	if v.WAF != "Cloudflare" {
		t.Errorf("expected Cloudflare vendor; got %q", v.WAF)
	}
}

func TestClassify_RateLimited(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "30")
	v := Classify(429, h, []byte("slow down"))
	if v.Kind != RateLimited || !v.Blocked {
		t.Fatalf("expected rate-limited; got %+v", v)
	}
}

func TestClassify_Clean(t *testing.T) {
	v := Classify(200, http.Header{}, []byte("<html>welcome</html>"))
	if v.Blocked || v.Kind != Clean {
		t.Fatalf("clean response must not be flagged; got %+v", v)
	}
}

func TestMonitor_FirstBlockOnce(t *testing.T) {
	m := &Monitor{}
	if m.Observe(Verdict{Blocked: false}) { t.Error("clean must not report first-block") }
	if !m.Observe(Verdict{Blocked: true, WAF: "X"}) { t.Error("first block must report true") }
	if m.Observe(Verdict{Blocked: true}) { t.Error("second block must not re-report") }
	total, blocked, rate, vendor := m.Stats()
	if total != 3 || blocked != 2 || rate == 0 || vendor != "X" {
		t.Errorf("unexpected stats: total=%d blocked=%d rate=%.2f vendor=%s", total, blocked, rate, vendor)
	}
}
