package templates

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuiltinLoads(t *testing.T) {
	tmpls, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpls) < 3 {
		t.Fatalf("expected several built-in templates, got %d", len(tmpls))
	}
}

func TestEngineMatchesGitConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/config" {
			w.WriteHeader(200)
			w.Write([]byte("[core]\n\trepositoryformatversion = 0\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	tmpls, _ := Builtin()
	eng := New(tmpls)
	hits, err := eng.Run(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var gotGit bool
	for _, h := range hits {
		if h.TemplateID == "git-config-exposure" {
			gotGit = true
		}
	}
	if !gotGit {
		t.Fatalf("expected git-config-exposure hit; got %+v", hits)
	}
}

func TestEngineNoFalsePositive(t *testing.T) {
	// A server that 404s everything must yield no hits.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("not found"))
	}))
	defer srv.Close()

	tmpls, _ := Builtin()
	hits, err := New(tmpls).Run(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("clean server must yield no template hits, got %+v", hits)
	}
}

func TestParseCustomTemplate(t *testing.T) {
	yaml := []byte(`
id: custom-check
info:
  name: Custom Check
  severity: low
requests:
  - method: GET
    path: /
    matchers:
      - type: word
        words: ["hello"]
`)
	tmpl, err := Parse(yaml)
	if err != nil {
		t.Fatal(err)
	}
	if tmpl.ID != "custom-check" || len(tmpl.Requests) != 1 {
		t.Fatalf("template parsed wrong: %+v", tmpl)
	}
}

// TestCompatible_RejectsMultiRequestAndInternal locks the zero-FP guard: a
// template using flow / multiple requests / internal-only preconditions (like
// Nuclei's apache-server-status-localhost) must be rejected, while a plain
// single-request exposure template is accepted.
func TestCompatible_RejectsMultiRequestAndInternal(t *testing.T) {
	multi := `
id: x-flow
info: {name: X, severity: low}
flow: http(1) && http(2)
http:
  - method: GET
    path: ["{{BaseURL}}/server-status"]
    matchers:
      - type: status
        status: [403,404,401]
        internal: true
  - method: GET
    path: ["{{BaseURL}}/server-status"]
    matchers:
      - type: word
        words: ["Apache Server Status"]
`
	tm, err := Parse([]byte(multi))
	if err != nil {
		t.Fatal(err)
	}
	if tm.Compatible() {
		t.Error("multi-request/flow/internal template must be rejected (FP risk)")
	}

	single := `
id: x-single
info: {name: X, severity: high}
http:
  - method: GET
    path: ["{{BaseURL}}/.git/config"]
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["[core]"]
`
	ts, err := Parse([]byte(single))
	if err != nil {
		t.Fatal(err)
	}
	if !ts.Compatible() {
		t.Error("plain single-request exposure template must be accepted")
	}
}

// TestBuiltinLoadsOfficialSet ensures the embedded official Nuclei set loads.
func TestBuiltinLoadsOfficialSet(t *testing.T) {
	b, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 250 {
		t.Errorf("expected the bundled official template set (>=250); got %d", len(b))
	}
	for _, tm := range b {
		if !tm.Compatible() {
			t.Errorf("embedded template %s is not engine-compatible", tm.ID)
		}
	}
}
