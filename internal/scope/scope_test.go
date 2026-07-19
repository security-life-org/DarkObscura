package scope

import (
	"net"
	"testing"
)

func TestBlocksPrivateAndMetadata(t *testing.T) {
	g := New("", false) // no scope, block private
	blocked := []string{
		"http://127.0.0.1/", "http://10.0.0.5/", "http://192.168.1.1/",
		"http://169.254.169.254/latest/meta-data/", "http://[::1]/", "http://100.64.0.1/",
	}
	for _, u := range blocked {
		if err := g.AllowURL(u); err == nil {
			t.Errorf("expected %s to be BLOCKED (SSRF), but it was allowed", u)
		}
	}
}

func TestAllowPrivateWhenPermitted(t *testing.T) {
	g := New("", true) // allow private (e.g. local testing)
	for _, u := range []string{"http://127.0.0.1:8099/", "http://10.0.0.5/"} {
		if err := g.AllowURL(u); err != nil {
			t.Errorf("with allowPrivate, %s should be allowed: %v", u, err)
		}
	}
}

func TestHostAllowlist(t *testing.T) {
	g := New(".example.com, target.test", true)
	// allowHost is the host-matching layer (no DNS).
	if err := g.allowHost("app.example.com"); err != nil {
		t.Errorf("app.example.com should be in scope: %v", err)
	}
	if err := g.allowHost("target.test"); err != nil {
		t.Errorf("target.test should be in scope: %v", err)
	}
	if err := g.allowHost("evil.com"); err == nil {
		t.Errorf("evil.com must be OUT of scope")
	}
}

func TestCIDRScope(t *testing.T) {
	g := New("203.0.113.0/24", true)
	if !g.Scoped() {
		t.Fatal("expected scoped")
	}
	if err := g.allowIP(net.ParseIP("203.0.113.7")); err != nil {
		t.Errorf("203.0.113.7 in CIDR should be allowed: %v", err)
	}
	if err := g.allowIP(net.ParseIP("8.8.8.8")); err == nil {
		t.Errorf("8.8.8.8 outside CIDR must be blocked")
	}
}

func TestIsBlocked(t *testing.T) {
	cases := map[string]bool{
		"169.254.169.254": true, "127.0.0.1": true, "10.1.2.3": true,
		"192.168.0.1": true, "100.64.0.1": true,
		"8.8.8.8": false, "1.1.1.1": false, "93.184.216.34": false,
	}
	for ip, want := range cases {
		if got := isBlocked(net.ParseIP(ip)); got != want {
			t.Errorf("isBlocked(%s) = %v, want %v", ip, got, want)
		}
	}
}
