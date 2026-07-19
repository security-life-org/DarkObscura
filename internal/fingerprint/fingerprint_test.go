package fingerprint

import (
	"net/http"
	"testing"
)

func TestDetect_ConfirmedSignals(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx/1.25.1")
	h.Set("X-Powered-By", "PHP/8.1.2")
	h.Add("Set-Cookie", "wordpress_logged_in_abc=1; Path=/")
	body := []byte(`<html><head><meta name="generator" content="WordPress 6.4.2"><script src="/wp-content/themes/x/app.js"></script><script src="/js/jquery-3.6.0.min.js"></script></head></html>`)

	techs := Detect(h, body, "/index.php")
	byName := map[string]Tech{}
	for _, te := range techs {
		byName[te.Name] = te
	}
	// Deterministic → confirmed.
	for _, name := range []string{"WordPress", "PHP", "nginx"} {
		if byName[name].Confidence != Confirmed {
			t.Errorf("%s must be confirmed; got %q", name, byName[name].Confidence)
		}
	}
	if byName["WordPress"].Version != "6.4.2" {
		t.Errorf("expected WordPress version 6.4.2; got %q", byName["WordPress"].Version)
	}
	if byName["PHP"].Version != "8.1.2" {
		t.Errorf("expected PHP version 8.1.2; got %q", byName["PHP"].Version)
	}
	// jQuery is only a shared-library hint → must NOT be confirmed.
	if byName["jQuery"].Confidence == Confirmed {
		t.Errorf("jQuery must not be confirmed (heuristic only)")
	}
	if len(ConfirmedOnly(techs)) == 0 {
		t.Errorf("expected at least one confirmed tech")
	}
	for _, c := range ConfirmedOnly(techs) {
		if c.Confidence != Confirmed {
			t.Errorf("ConfirmedOnly leaked %s (%s)", c.Name, c.Confidence)
		}
	}
}

func TestDetect_NoFalseConfirm(t *testing.T) {
	// A plain page with only a jQuery reference must yield zero confirmed tech.
	body := []byte(`<html><script src="/assets/jquery.min.js"></script></html>`)
	techs := Detect(http.Header{}, body, "/")
	if n := len(ConfirmedOnly(techs)); n != 0 {
		t.Errorf("expected zero confirmed tech on a heuristic-only page; got %d", n)
	}
}
