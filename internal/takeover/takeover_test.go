package takeover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheck_ConfirmedTakeover(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>There isn't a GitHub Pages site here.</html>"))
	}))
	defer srv.Close()
	c := &Checker{Client: srv.Client(), Resolve: func(ctx context.Context, host string) (string, error) {
		return "victim.github.io.", nil
	}}
	// point fetch at the test server by using its host
	host := strings.TrimPrefix(srv.URL, "http://")
	f, err := c.Check(context.Background(), host)
	if err != nil { t.Fatal(err) }
	if f == nil || !f.Confirmed || f.Provider != "GitHub Pages" {
		t.Fatalf("expected confirmed GitHub Pages takeover; got %v", f)
	}
}

func TestCheck_LiveSite_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>Welcome to my live site</html>"))
	}))
	defer srv.Close()
	c := &Checker{Client: srv.Client(), Resolve: func(ctx context.Context, host string) (string, error) {
		return "victim.github.io.", nil
	}}
	host := strings.TrimPrefix(srv.URL, "http://")
	f, _ := c.Check(context.Background(), host)
	if f != nil { t.Fatalf("live site must NOT be flagged; got %v", f) }
}
