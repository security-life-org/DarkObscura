package gui

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	neturl "net/url"
	"time"

	"github.com/security-life-org/DarkObscura/internal/clientside"
	"github.com/security-life-org/DarkObscura/internal/cve"
	"github.com/security-life-org/DarkObscura/internal/dom"
	"github.com/security-life-org/DarkObscura/internal/dynamic"
	"github.com/security-life-org/DarkObscura/internal/fingerprint"
	"github.com/security-life-org/DarkObscura/internal/grpcfuzz"
	"github.com/security-life-org/DarkObscura/internal/secrets"
	"github.com/security-life-org/DarkObscura/internal/takeover"
	"github.com/security-life-org/DarkObscura/internal/templates"
	"github.com/security-life-org/DarkObscura/internal/waf"
)

// wafHandler — actively probe whether a WAF is present and blocking attacks.
func wafHandler(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if target == "" || !authorized(r) {
			http.Error(w, "url and authorized=1 required", http.StatusBadRequest)
			return
		}
		if denyScope(w, target) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		res, err := waf.Probe(ctx, scopedClient(20*time.Second), target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		log.Info("waf probe", "url", target, "waf", res.WAF, "blocksAttack", res.BlocksAttack)
		writeJSON(w, res)
	}
}

// authorized reports whether the request carries the authorization flag.
func authorized(r *http.Request) bool { return r.URL.Query().Get("authorized") == "1" }

// fetchScoped GETs a URL through the scoped client and returns headers + body.
func fetchScoped(ctx context.Context, url string) (http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "DarkObscura")
	resp, err := scopedClient(20 * time.Second).Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.Header, body, nil
}

// fingerprintHandler — passive CMS/tech detection + CVE correlation.
func fingerprintHandler(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if target == "" || !authorized(r) {
			http.Error(w, "url and authorized=1 required", http.StatusBadRequest)
			return
		}
		if denyScope(w, target) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		hdr, body, err := fetchScoped(ctx, target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		path := "/"
		if u, e := neturl.Parse(target); e == nil {
			path = u.Path
		}
		techs := fingerprint.Detect(hdr, body, path)
		vulns := cve.Correlate(techs)
		log.Info("fingerprint", "url", target, "techs", len(techs), "cves", len(vulns))
		writeJSON(w, map[string]any{"techs": techs, "cves": vulns})
	}
}

// templatesHandler — run built-in + official Nuclei templates against a target.
func templatesHandler(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if target == "" || !authorized(r) {
			http.Error(w, "url and authorized=1 required", http.StatusBadRequest)
			return
		}
		if denyScope(w, target) {
			return
		}
		tmpls, err := templates.Builtin()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		eng := templates.New(tmpls)
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		hits, err := eng.Run(ctx, target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		log.Info("templates", "url", target, "count", eng.Count(), "hits", len(hits))
		writeJSON(w, map[string]any{"count": eng.Count(), "hits": hits})
	}
}

// clientsideHandler — CORS / cache-poisoning / CSP checks.
func clientsideHandler(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if target == "" || !authorized(r) {
			http.Error(w, "url and authorized=1 required", http.StatusBadRequest)
			return
		}
		if denyScope(w, target) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		fs, err := clientside.New(scopedClient(15 * time.Second)).Scan(ctx, target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]any{"findings": fs})
	}
}

// domHandler — static DOM-XSS sink/source analysis of the page body.
func domHandler(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if target == "" || !authorized(r) {
			http.Error(w, "url and authorized=1 required", http.StatusBadRequest)
			return
		}
		if denyScope(w, target) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		_, body, err := fetchScoped(ctx, target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]any{"findings": dom.Analyze(body), "headless": dom.Available()})
	}
}

// secretsHandler — harvest scripts and scan bodies for leaked secrets.
func secretsHandler(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if target == "" || !authorized(r) {
			http.Error(w, "url and authorized=1 required", http.StatusBadRequest)
			return
		}
		if denyScope(w, target) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		client := scopedClient(20 * time.Second)
		surface, _ := dynamic.Harvest(ctx, target, dynamic.Options{Client: client})
		var matches []secrets.Match
		urls := []string{target}
		if surface != nil {
			urls = append(urls, surface.Scripts...)
		}
		for _, u := range urls {
			_, body, err := fetchScoped(ctx, u)
			if err != nil {
				continue
			}
			matches = append(matches, secrets.Scan(body)...)
		}
		writeJSON(w, map[string]any{"secrets": matches})
	}
}

// takeoverHandler — subdomain takeover check for a host.
func takeoverHandler(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if host == "" || !authorized(r) {
			http.Error(w, "host and authorized=1 required", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		f, err := takeover.New().Check(ctx, host)
		if err != nil {
			writeJSON(w, map[string]any{"finding": nil, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"finding": f})
	}
}

// grpcHandler — enumerate + fuzz a gRPC endpoint via reflection.
func grpcHandler(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		if target == "" || !authorized(r) {
			http.Error(w, "target (host:port) and authorized=1 required", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		res, err := grpcfuzz.Fuzz(ctx, target, r.URL.Query().Get("tls") == "1")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, res)
	}
}
