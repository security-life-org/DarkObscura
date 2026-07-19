// Package gui serves the embedded DarkObscura web UI and a small in-process API
// directly from the Go binary, so `dobscura --gui` is fully self-contained: no
// npm, no Vite, no separate backend. The UI assets are compiled into the binary
// via go:embed.
package gui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	neturl "net/url"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/security-life-org/DarkObscura/internal/scope"

	"github.com/security-life-org/DarkObscura/internal/crawl"
	"github.com/security-life-org/DarkObscura/internal/engine"
	"github.com/security-life-org/DarkObscura/internal/exploit"
	"github.com/security-life-org/DarkObscura/internal/importer"
	"github.com/security-life-org/DarkObscura/internal/parser"
	"github.com/security-life-org/DarkObscura/internal/passive"
	"github.com/security-life-org/DarkObscura/internal/templates"
)

//go:embed webui
var webui embed.FS

// Options configures the GUI server.
type Options struct {
	Addr         string // listen address, e.g. "127.0.0.1:8422"
	Open         bool   // auto-open the browser
	Logger       *slog.Logger
	Scope        string // comma-separated in-scope hosts/domains/CIDRs ("" = any public)
	AllowPrivate bool   // permit private/loopback/metadata targets (e.g. local testing)
	RequireAuth  bool   // require the bearer token on /api/* routes
	Token        string // API token; generated if empty and RequireAuth is set
	Version      string // build version, surfaced at /version
}

// package-level guard + token shared by all handlers (single server instance).
var (
	guard   *scope.Guard
	apiKey  string
	version = "dev"
)

// Serve starts the GUI HTTP server (static UI + API) until ctx is cancelled.
func Serve(ctx context.Context, opts Options) error {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	sub, err := fs.Sub(webui, "webui")
	if err != nil {
		return err
	}

	guard = scope.New(opts.Scope, opts.AllowPrivate)
	if opts.Version != "" {
		version = opts.Version
	}
	if opts.RequireAuth {
		apiKey = opts.Token
		if apiKey == "" {
			apiKey = randomToken()
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/scan", scanHandler(log))
	mux.HandleFunc("/api/scan/stream", streamHandler(log))
	mux.HandleFunc("/api/deepscan/stream", deepScanHandler(log))
	mux.HandleFunc("/api/attack/stream", attackHandler(log))
	mux.HandleFunc("/api/crawl", crawlHandler(log))
	mux.HandleFunc("/api/import", importHandler(log))
	mux.HandleFunc("/api/race", raceHandler(log))
	mux.HandleFunc("/api/smuggle", smuggleHandler(log))
	mux.HandleFunc("/api/repeat", repeatHandler(log))
	mux.HandleFunc("/api/probe", probeHandler(log))
	mux.HandleFunc("/api/classify", classifyHandler)
	mux.HandleFunc("/api/fingerprint", fingerprintHandler(log))
	mux.HandleFunc("/api/templates", templatesHandler(log))
	mux.HandleFunc("/api/clientside", clientsideHandler(log))
	mux.HandleFunc("/api/dom", domHandler(log))
	mux.HandleFunc("/api/secrets", secretsHandler(log))
	mux.HandleFunc("/api/takeover", takeoverHandler(log))
	mux.HandleFunc("/api/grpc", grpcHandler(log))
	mux.HandleFunc("/api/waf", wafHandler(log))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": "ok", "version": version})
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"version": version, "scoped": guard.Scoped(), "authRequired": opts.RequireAuth})
	})

	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return fmt.Errorf("gui: listen %s: %w", opts.Addr, err)
	}
	srv := &http.Server{Handler: withMiddleware(mux, opts.RequireAuth), ReadHeaderTimeout: 15 * time.Second}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	url := "http://" + ln.Addr().String()
	uiURL := url
	if apiKey != "" {
		uiURL = url + "/?token=" + apiKey
	}
	log.Info("DarkObscura ready", "url", url, "version", version,
		"scope", scopeDesc(opts), "auth", opts.RequireAuth)
	fmt.Printf("\n  DarkObscura %s  →  %s\n", version, uiURL)
	fmt.Printf("  scope: %s\n", scopeDesc(opts))
	if apiKey != "" {
		fmt.Printf("  api token: %s\n", apiKey)
	}
	if isPublicBind(opts.Addr) {
		fmt.Printf("  ⚠ WARNING: bound to a non-loopback address — ensure auth is on and access is restricted.\n")
	}
	fmt.Printf("  (Ctrl+C to stop)\n\n")
	if opts.Open {
		openBrowser(uiURL, log)
	}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// withMiddleware adds security headers and (optionally) bearer-token auth.
func withMiddleware(next http.Handler, requireAuth bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
		if requireAuth && strings.HasPrefix(r.URL.Path, "/api/") {
			if !validToken(r) {
				http.Error(w, "unauthorized: provide the API token (Authorization: Bearer … or ?token=…)", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// validToken checks the bearer token from header or query using constant-time
// comparison.
func validToken(r *http.Request) bool {
	if apiKey == "" {
		return true
	}
	tok := r.URL.Query().Get("token")
	if tok == "" {
		if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
			tok = strings.TrimPrefix(a, "Bearer ")
		}
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(apiKey)) == 1
}

func randomToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func scopeDesc(o Options) string {
	base := o.Scope
	if base == "" {
		base = "any public host"
	}
	if o.AllowPrivate {
		return base + " (private/loopback permitted)"
	}
	return base + " (private/reserved/metadata blocked)"
}

func isPublicBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return host != "" && host != "127.0.0.1" && host != "localhost" && host != "::1"
}

// scanRequest is the POST body for /api/scan.
type scanRequest struct {
	URL        string `json:"url"`
	Authorized bool   `json:"authorized"`
}

// paramDTO / findingDTO are the JSON shapes the UI consumes.
type paramDTO struct {
	Name     string   `json:"name"`
	Value    string   `json:"value"`
	Risk     string   `json:"risk"`
	Location string   `json:"location"`
	Reasons  []string `json:"reasons"`
	Probed   bool     `json:"probed"`
}
type findingDTO struct {
	Class       string   `json:"class"`
	Severity    string   `json:"severity"`
	Param       string   `json:"param"`
	Payload     string   `json:"payload"`
	Marker      string   `json:"marker,omitempty"`
	Endpoint    string   `json:"endpoint,omitempty"` // which discovered endpoint (deep scan)
	VerifiedVia string   `json:"verifiedVia"`
	Evidence    []string `json:"evidence"`
	Stages      []string `json:"stages"` // which pipeline stages ran/passed
}

// endpointDTO describes one discovered, de-duplicated endpoint in a deep scan.
type endpointDTO struct {
	URL      string   `json:"url"`
	Path     string   `json:"path"`
	Params   []string `json:"params"`
	Findings int      `json:"findings"`
}

type deepResponse struct {
	Origin    string          `json:"origin"`
	Endpoints []endpointDTO   `json:"endpoints"`
	Findings  []findingDTO    `json:"findings"`
	Summary   summaryDTO      `json:"summary"`
	Passive   []passive.Issue `json:"passive"`
}
type summaryDTO struct {
	Target       string `json:"target"`
	Host         string `json:"host"`
	DurationMs   int64  `json:"durationMs"`
	ParamsFound  int    `json:"paramsFound"`
	ParamsProbed int    `json:"paramsProbed"`
	Total        int    `json:"total"`
	Critical     int    `json:"critical"`
	High         int    `json:"high"`
	Medium       int    `json:"medium"`
	Low          int    `json:"low"`
}
type captureDTO struct {
	Request  string `json:"request"`
	Response string `json:"response"`
	Status   int    `json:"status"`
}
type scanResponse struct {
	Params   []paramDTO   `json:"params"`
	Findings []findingDTO `json:"findings"`
	Summary  summaryDTO      `json:"summary"`
	Capture  *captureDTO     `json:"capture,omitempty"`
	Passive  []passive.Issue `json:"passive"`
}

// performScan discovers params, captures a real baseline flow, and runs the
// verification-gated fuzzer. onProgress (may be nil) receives live events.
func performScan(ctx context.Context, log *slog.Logger, url string, onProgress exploit.ProgressFunc) (scanResponse, error) {
	// Discover params for the graph.
	ext := parser.NewExtractor(nil)
	var params []paramDTO
	probed := 0
	if q := queryOf(url); q != "" {
		for _, p := range ext.FromQuery(q) {
			isProbed := p.Risk >= parser.RiskMedium
			if isProbed {
				probed++
			}
			params = append(params, paramDTO{
				Name: p.Name, Value: p.Value, Risk: p.Risk.String(),
				Location: p.Location, Reasons: p.Reasons, Probed: isProbed,
			})
		}
	}

	// Capture a real request/response so Tactical shows live data, not a mock,
	// and run the passive audit on it (zero extra requests).
	capture, hdr, cbody, scheme := captureFlow(ctx, url)
	passiveIssues := passive.Audit(scheme, 0, hdr, cbody)

	// Templated checks (Nuclei-style) against the origin — exposed files, panels,
	// misconfig — surfaced alongside the passive issues.
	if u, err := neturl.Parse(url); err == nil {
		origin := u.Scheme + "://" + u.Host
		if tmpls, terr := templates.Builtin(); terr == nil && len(tmpls) > 0 {
			if hits, herr := templates.New(tmpls).Run(ctx, origin); herr == nil {
				for _, h := range hits {
					passiveIssues = append(passiveIssues, passive.Issue{
						Class: "template:" + h.TemplateID, Severity: h.Severity, Title: h.Name,
						Detail: "templated check matched at " + h.URL, Evidence: h.Matched})
				}
			}
		}
	}

	if onProgress != nil {
		for _, iss := range passiveIssues {
			onProgress(exploit.Progress{Kind: "passive", Class: iss.Class,
				Severity: iss.Severity, Message: iss.Title})
		}
	}

	sess, err := scopedSession()
	if err != nil {
		return scanResponse{}, err
	}
	fuzzer := exploit.NewFuzzer(sess, exploit.NewVerifier(nil), nil)
	fuzzer.OnProgress = onProgress

	log.Info("gui scan", "url", url, "params", len(params))
	started := time.Now()
	findings, err := fuzzer.FuzzURL(ctx, url)
	if err != nil {
		return scanResponse{}, err
	}
	elapsed := time.Since(started)

	resp := scanResponse{Params: params, Capture: capture, Passive: passiveIssues}
	sev := map[string]int{}
	for _, f := range findings {
		resp.Findings = append(resp.Findings, findingDTO{
			Class: f.Class, Severity: string(f.Severity), Param: f.Param,
			Payload: f.Payload, Marker: f.Marker, VerifiedVia: f.VerifiedVia, Evidence: f.Evidence,
			Stages: stagesFor(f.VerifiedVia),
		})
		sev[string(f.Severity)]++
	}
	resp.Summary = summaryDTO{
		Target: url, Host: hostOf(url), DurationMs: elapsed.Milliseconds(),
		ParamsFound: len(params), ParamsProbed: probed, Total: len(findings),
		Critical: sev["critical"], High: sev["high"], Medium: sev["medium"], Low: sev["low"],
	}
	return resp, nil
}

// canonicalEndpoint returns a stable identity for an endpoint: METHOD + path +
// the sorted set of parameter NAMES (ignoring values), so /p?id=1 and /p?id=2
// collapse to one endpoint. This is the "precise identifier" that dedups the
// crawl surface into distinct testable endpoints.
func canonicalEndpoint(rawURL string) string {
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	names := make([]string, 0, len(u.Query()))
	for k := range u.Query() {
		names = append(names, k)
	}
	sort.Strings(names)
	return u.Path + "?" + strings.Join(names, ",")
}

// performDeepScan crawls the origin of startURL, de-duplicates the discovered
// endpoints by canonical identity, and scans each one (fast mode), aggregating
// findings. This is the "just give me a URL" flow.
func performDeepScan(ctx context.Context, log *slog.Logger, startURL string, onProgress exploit.ProgressFunc) (deepResponse, error) {
	emit := func(kind, msg string) {
		if onProgress != nil {
			onProgress(exploit.Progress{Kind: kind, Message: msg})
		}
	}
	u, err := neturl.Parse(startURL)
	if err != nil {
		return deepResponse{}, err
	}
	origin := u.Scheme + "://" + u.Host
	out := deepResponse{Origin: origin}

	// 1. Crawl the origin.
	emit("scan-start", u.Host)
	emit("deep", "🕷 crawling "+origin+" to discover the attack surface…")
	cres, _ := crawl.Crawl(ctx, origin, crawl.Options{MaxDepth: 2, MaxPages: 40})
	emit("deep", fmt.Sprintf("crawl found %d pages, %d raw endpoints, %d forms",
		len(cres.Pages), len(cres.Endpoints), len(cres.Forms)))

	// 2. Collect + de-duplicate endpoints by canonical identity.
	candidates := append([]string{}, cres.Endpoints...)
	if u.RawQuery != "" {
		candidates = append(candidates, startURL) // include the given URL if it has params
	}
	seen := map[string]bool{}
	var endpoints []string
	for _, c := range candidates {
		key := canonicalEndpoint(c)
		if !seen[key] {
			seen[key] = true
			endpoints = append(endpoints, c)
		}
	}
	emit("deep", fmt.Sprintf("identified %d unique endpoints (deduplicated by path+params)", len(endpoints)))

	// 3. Passive audit + templated checks once on the origin.
	capture, hdr, cbody, scheme := captureFlow(ctx, origin+"/")
	_ = capture
	out.Passive = passive.Audit(scheme, 0, hdr, cbody)
	if tmpls, terr := templates.Builtin(); terr == nil {
		if hits, herr := templates.New(tmpls).Run(ctx, origin); herr == nil {
			for _, h := range hits {
				out.Passive = append(out.Passive, passive.Issue{
					Class: "template:" + h.TemplateID, Severity: h.Severity, Title: h.Name,
					Detail: "templated check matched at " + h.URL, Evidence: h.Matched})
			}
		}
	}
	if onProgress != nil {
		for _, iss := range out.Passive {
			onProgress(exploit.Progress{Kind: "passive", Class: iss.Class, Severity: iss.Severity, Message: iss.Title})
		}
	}

	// 4. Scan each endpoint (fast mode — no slow time-based probes). Findings are
	// de-duplicated to one per (endpoint, parameter, class) so multiple payload
	// variants of the same issue collapse into a single precise finding.
	ext := parser.NewExtractor(nil)
	sev := map[string]int{}
	seenFinding := map[string]bool{}
	started := time.Now()
	for i, ep := range endpoints {
		epURL, _ := neturl.Parse(ep)
		emit("deep", fmt.Sprintf("scanning endpoint %d/%d · %s", i+1, len(endpoints), epURL.Path))

		var epParams []string
		for _, p := range ext.FromQuery(epURL.RawQuery) {
			epParams = append(epParams, p.Name)
		}

		sess, serr := scopedSession()
		if serr != nil {
			continue
		}
		fz := exploit.NewFuzzer(sess, exploit.NewVerifier(nil), nil)
		fz.FastMode = true
		fz.OnProgress = onProgress
		findings, _ := fz.FuzzURL(ctx, ep)

		epCount := 0
		for _, f := range findings {
			key := ep + "|" + f.Param + "|" + f.Class
			if seenFinding[key] {
				continue
			}
			seenFinding[key] = true
			epCount++
			out.Findings = append(out.Findings, findingDTO{
				Class: f.Class, Severity: string(f.Severity), Param: f.Param, Payload: f.Payload,
				Marker: f.Marker, Endpoint: ep, VerifiedVia: f.VerifiedVia, Evidence: f.Evidence,
				Stages: stagesFor(f.VerifiedVia),
			})
			sev[string(f.Severity)]++
		}
		out.Endpoints = append(out.Endpoints, endpointDTO{
			URL: ep, Path: epURL.Path, Params: epParams, Findings: epCount})
	}

	out.Summary = summaryDTO{
		Target: startURL, Host: u.Host, DurationMs: time.Since(started).Milliseconds(),
		ParamsFound: countParams(out.Endpoints), ParamsProbed: countParams(out.Endpoints),
		Total: len(out.Findings), Critical: sev["critical"], High: sev["high"],
		Medium: sev["medium"], Low: sev["low"],
	}
	log.Info("deep scan", "origin", origin, "endpoints", len(endpoints), "findings", len(out.Findings))
	return out, nil
}

func countParams(eps []endpointDTO) int {
	n := 0
	for _, e := range eps {
		n += len(e.Params)
	}
	return n
}

func scanHandler(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req scanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if !req.Authorized {
			http.Error(w, "authorization required: confirm you may test this target", http.StatusForbidden)
			return
		}
		if denyScope(w, req.URL) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()
		resp, err := performScan(ctx, log, req.URL, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, resp)
	}
}

// streamHandler runs a scan and streams live progress over Server-Sent Events,
// then a final "done" event with the full result. EventSource uses GET, so the
// target and authorization arrive as query parameters.
func streamHandler(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		url := r.URL.Query().Get("url")
		if r.URL.Query().Get("authorized") != "1" {
			http.Error(w, "authorization required", http.StatusForbidden)
			return
		}
		if denyScope(w, url) {
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		sendEvent := func(event string, v any) {
			blob, _ := json.Marshal(v)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, blob)
			flusher.Flush()
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()

		onProgress := func(p exploit.Progress) { sendEvent("progress", p) }
		resp, err := performScan(ctx, log, url, onProgress)
		if err != nil {
			sendEvent("scanerror", map[string]string{"error": err.Error()})
			return
		}
		sendEvent("done", resp)
	}
}

// attackHandler runs Attack Mode against a single confirmed finding, streaming
// live exploitation progress (e.g. characters exfiltrated via blind SQLi) and a
// final "evidence" event proving the vulnerability is a true positive.
func attackHandler(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		q := r.URL.Query()
		if q.Get("authorized") != "1" {
			http.Error(w, "authorization required", http.StatusForbidden)
			return
		}
		rawURL, param, class := q.Get("url"), q.Get("param"), q.Get("class")
		payload, marker := q.Get("payload"), q.Get("marker")

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		send := func(event string, v any) {
			blob, _ := json.Marshal(v)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, blob)
			flusher.Flush()
		}

		u, err := neturl.Parse(rawURL)
		if err != nil {
			send("attackerror", map[string]string{"error": "bad url"})
			return
		}
		if guard != nil {
			if serr := guard.AllowURL(rawURL); serr != nil {
				send("attackerror", map[string]string{"error": serr.Error()})
				return
			}
		}
		sess, err := scopedSession()
		if err != nil {
			send("attackerror", map[string]string{"error": err.Error()})
			return
		}
		sendFn := exploit.BuildSend(sess, u, param)
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()

		att := exploit.NewAttacker()
		att.OnProgress = func(p exploit.Progress) { send("progress", p) }
		log.Info("attack mode", "class", class, "param", param)

		var ev exploit.Evidence
		switch class {
		case "sqli-time-blind":
			ev, err = att.ExtractTimeSQLi(ctx, sendFn, "1")
		case "reflected-xss":
			poc := u.String()
			if q2, e := neturl.ParseQuery(u.RawQuery); e == nil {
				q2.Set(param, payload)
				uu := *u
				uu.RawQuery = q2.Encode()
				poc = uu.String()
			}
			ev, err = att.ProveXSS(ctx, sendFn, payload, marker, poc)
		case "path-traversal-lfi", "path-traversal-lfi (header)":
			ev, err = att.DumpFile(ctx, sendFn, payload)
		default:
			send("done", exploit.Evidence{Kind: class, Proven: true,
				Summary: "confirmed at detection time — no further active exploitation needed"})
			return
		}
		if err != nil {
			send("attackerror", map[string]string{"error": err.Error()})
			return
		}
		send("done", ev)
	}
}

// deepScanHandler crawls an origin and scans every discovered endpoint, streaming
// live progress and a final aggregated result.
func deepScanHandler(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		url := r.URL.Query().Get("url")
		if r.URL.Query().Get("authorized") != "1" {
			http.Error(w, "authorization required", http.StatusForbidden)
			return
		}
		if denyScope(w, url) {
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		send := func(event string, v any) {
			blob, _ := json.Marshal(v)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, blob)
			flusher.Flush()
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()
		res, err := performDeepScan(ctx, log, url, func(p exploit.Progress) { send("progress", p) })
		if err != nil {
			send("scanerror", map[string]string{"error": err.Error()})
			return
		}
		send("done", res)
	}
}

// captureFlow performs one real GET and returns the raw request/response text
// (bounded) for the Tactical inspector. Errors degrade to a nil capture.
func captureFlow(ctx context.Context, rawURL string) (*captureDTO, http.Header, []byte, string) {
	u, err := neturl.Parse(rawURL)
	if err != nil {
		return nil, nil, nil, ""
	}
	scheme := u.Scheme
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, nil, scheme
	}
	req.Header.Set("User-Agent", "DarkObscura/0.1")
	path := u.RequestURI()
	reqStr := fmt.Sprintf("GET %s HTTP/1.1\nHost: %s\nUser-Agent: DarkObscura/0.1\nAccept: */*", path, u.Host)

	resp, err := scopedClient(20 * time.Second).Do(req)
	if err != nil {
		return &captureDTO{Request: reqStr, Response: "(no response: " + err.Error() + ")"}, nil, nil, scheme
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	var hdr strings.Builder
	fmt.Fprintf(&hdr, "HTTP/1.1 %s\n", resp.Status)
	for k, vv := range resp.Header {
		for _, v := range vv {
			fmt.Fprintf(&hdr, "%s: %s\n", k, v)
		}
	}
	respStr := hdr.String() + "\n" + string(body)
	return &captureDTO{Request: reqStr, Response: respStr, Status: resp.StatusCode}, resp.Header, body, scheme
}

// crawlHandler spiders the given URL's origin and returns discovered endpoints.
func crawlHandler(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if target == "" {
			http.Error(w, "url required", http.StatusBadRequest)
			return
		}
		if denyScope(w, target) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		res, err := crawl.Crawl(ctx, target, crawl.Options{MaxDepth: 2, MaxPages: 60, Client: scopedClient(15 * time.Second)})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		log.Info("crawl", "start", target, "pages", len(res.Pages), "endpoints", len(res.Endpoints))
		writeJSON(w, res)
	}
}

// importHandler parses a posted OpenAPI/Swagger spec into scannable endpoints.
func importHandler(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		base := r.URL.Query().Get("base")
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		eps, err := importer.ParseOpenAPI(body, base)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Info("import openapi", "endpoints", len(eps))
		writeJSON(w, map[string]any{"endpoints": eps})
	}
}

// raceHandler runs a race-condition (TOCTOU) burst against a URL.
func raceHandler(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		marker := r.URL.Query().Get("marker")
		if target == "" || marker == "" {
			http.Error(w, "url and marker required", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("authorized") != "1" {
			http.Error(w, "authorization required", http.StatusForbidden)
			return
		}
		if denyScope(w, target) {
			return
		}
		attempts := 30
		sess, err := scopedSession()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		res, err := exploit.RaceTest(ctx, sess, target, marker, attempts, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		log.Info("race test", "url", target, "successes", res.Successes, "vulnerable", res.Vulnerable)
		writeJSON(w, res)
	}
}

// smuggleHandler runs an HTTP request-smuggling desync probe against a URL.
func smuggleHandler(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if target == "" {
			http.Error(w, "url required", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("authorized") != "1" {
			http.Error(w, "authorization required", http.StatusForbidden)
			return
		}
		if denyScope(w, target) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		res, err := exploit.DetectSmuggling(ctx, target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		log.Info("smuggle probe", "url", target, "vulnerable", res.Vulnerable)
		writeJSON(w, res)
	}
}

// repeatReq is a raw request to replay (Tactical repeater).
type repeatReq struct {
	Raw  string `json:"raw"`  // raw HTTP request text (request-line + headers + blank + body)
	Base string `json:"base"` // origin (scheme://host) to resolve the path against
}

// repeatHandler replays an edited raw HTTP request and returns the raw response.
func repeatHandler(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req repeatReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		method, target, headers, body := parseRawRequest(req.Raw, req.Base)
		if target == "" {
			http.Error(w, "could not parse request line", http.StatusBadRequest)
			return
		}
		if denyScope(w, target) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		var bodyR io.Reader
		if body != "" {
			bodyR = strings.NewReader(body)
		}
		hreq, err := http.NewRequestWithContext(ctx, method, target, bodyR)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for k, v := range headers {
			if strings.EqualFold(k, "host") {
				hreq.Host = v
				continue
			}
			hreq.Header.Set(k, v)
		}
		start := time.Now()
		rc := scopedClient(20 * time.Second)
		rc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := rc.Do(hreq)
		if err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		defer resp.Body.Close()
		rbody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var sb strings.Builder
		fmt.Fprintf(&sb, "HTTP/1.1 %s\n", resp.Status)
		for k, vv := range resp.Header {
			for _, v := range vv {
				fmt.Fprintf(&sb, "%s: %s\n", k, v)
			}
		}
		sb.WriteString("\n")
		sb.Write(rbody)
		log.Info("repeat", "method", method, "url", target, "status", resp.StatusCode)
		writeJSON(w, map[string]any{
			"status": resp.StatusCode, "elapsedMs": time.Since(start).Milliseconds(),
			"response": sb.String(), "length": len(rbody),
		})
	}
}

// parseRawRequest leniently parses a raw HTTP request into its parts and builds
// the absolute target URL from base + path.
func parseRawRequest(raw, base string) (method, target string, headers map[string]string, body string) {
	headers = map[string]string{}
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	parts := strings.SplitN(raw, "\n\n", 2)
	head := parts[0]
	if len(parts) == 2 {
		body = parts[1]
	}
	lines := strings.Split(head, "\n")
	if len(lines) == 0 {
		return
	}
	f := strings.Fields(lines[0])
	if len(f) < 2 {
		return
	}
	method = f[0]
	path := f[1]
	for _, ln := range lines[1:] {
		if i := strings.IndexByte(ln, ':'); i > 0 {
			headers[strings.TrimSpace(ln[:i])] = strings.TrimSpace(ln[i+1:])
		}
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		target = path
	} else {
		target = strings.TrimRight(base, "/") + path
	}
	return
}

// probeReq is a single manual payload injection (God payload console).
type probeReq struct {
	URL      string `json:"url"`
	Param    string `json:"param"`
	Location string `json:"location"` // query | header | cookie
	Payload  string `json:"payload"`
}

// probeHandler fires one manual request injecting a payload and returns the raw
// response plus quick heuristics (reflection, timing) — a manual fuzzing console.
func probeHandler(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var pr probeReq
		if err := json.NewDecoder(r.Body).Decode(&pr); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		u, err := neturl.Parse(pr.URL)
		if err != nil {
			http.Error(w, "bad url", http.StatusBadRequest)
			return
		}
		if denyScope(w, pr.URL) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()

		reqURL := pr.URL
		hreq, _ := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		switch pr.Location {
		case "header":
			hreq.Header.Set(pr.Param, pr.Payload)
		case "cookie":
			hreq.AddCookie(&http.Cookie{Name: pr.Param, Value: pr.Payload})
		default: // query
			q := u.Query()
			q.Set(pr.Param, pr.Payload)
			u.RawQuery = q.Encode()
			hreq.URL = u
		}
		start := time.Now()
		resp, err := scopedClient(20 * time.Second).Do(hreq)
		if err != nil {
			writeJSON(w, map[string]any{"error": err.Error()})
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		elapsed := time.Since(start).Milliseconds()
		reflected := pr.Payload != "" && strings.Contains(string(body), pr.Payload)
		log.Info("probe", "param", pr.Param, "loc", pr.Location, "status", resp.StatusCode)
		writeJSON(w, map[string]any{
			"status": resp.StatusCode, "elapsedMs": elapsed, "length": len(body),
			"reflected": reflected, "body": string(body[:min(len(body), 20000)]),
		})
	}
}

func classifyHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	value := r.URL.Query().Get("value")
	risk, reasons := parser.DefaultClassifier().Classify(name, value)
	writeJSON(w, map[string]any{"name": name, "risk": risk.String(), "reasons": reasons})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// denyScope rejects an out-of-scope target with 403 and returns true. Called at
// the entry of every handler that fetches a user-supplied URL — this is the
// SSRF / engagement-scope enforcement.
func denyScope(w http.ResponseWriter, target string) bool {
	if guard == nil {
		return false
	}
	if err := guard.AllowURL(target); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return true
	}
	return false
}

// scopedSession returns an engine session whose HTTP client dials only in-scope
// addresses (redirect- and rebind-proof).
func scopedSession() (*engine.Session, error) {
	sess, err := engine.NewSession()
	if err != nil {
		return nil, err
	}
	if guard != nil {
		sess.Client.Transport = guard.Transport()
	}
	return sess, nil
}

// scopedClient returns an HTTP client that enforces the scope guard.
func scopedClient(timeout time.Duration) *http.Client {
	if guard != nil {
		return guard.Client(timeout)
	}
	return &http.Client{Timeout: timeout}
}

// stagesFor reports which verification stages confirmed a finding, for the UI's
// pipeline visualization. Baseline + differential always run; the confirming
// stage depends on the verification method.
func stagesFor(verifiedVia string) []string {
	switch verifiedVia {
	case "time-series-analysis":
		return []string{"baseline", "differential", "time-series"}
	case "out-of-band-canary":
		return []string{"baseline", "differential", "oob-canary"}
	case "reflection-analysis":
		return []string{"baseline", "reflection"}
	case "template-evaluation":
		return []string{"baseline", "template-eval"}
	case "file-read-analysis":
		return []string{"baseline", "file-read"}
	case "redirect-location":
		return []string{"redirect-check"}
	case "differential-analysis":
		return []string{"baseline", "differential"}
	default:
		return []string{"baseline"}
	}
}

// hostOf returns the host component of a URL, or the raw string on parse failure.
func hostOf(raw string) string {
	if u, err := neturl.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

// queryOf extracts the raw query string from a URL without failing on odd input.
func queryOf(raw string) string {
	for i := 0; i < len(raw); i++ {
		if raw[i] == '?' {
			return raw[i+1:]
		}
	}
	return ""
}

// openBrowser best-effort launches the platform browser at url.
func openBrowser(url string, log *slog.Logger) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Warn("could not auto-open browser; open the URL manually", "url", url, "err", err)
	}
}
