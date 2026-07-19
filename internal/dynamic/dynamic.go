// Package dynamic harvests the "dynamic" attack surface of modern applications
// without a headless browser. Single-page apps rarely expose their real API in
// the server-rendered HTML — the endpoints live inside JavaScript bundles that a
// classic HTML crawler never reads. dynamic fetches the page and every linked
// script, then mines them for API paths, route templates, parameter names, and
// GraphQL/WebSocket endpoints. It is pure-Go (net/http + regexp) so it always
// compiles and needs no external Chrome binary.
//
// This is a discovery aid, not an exploit: it only performs GETs of the target
// and its own scripts. Callers must stay within an authorized scope.
package dynamic

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Surface is the aggregated dynamic attack surface discovered for a target.
type Surface struct {
	Origin     string
	Scripts    []string // absolute URLs of scripts that were fetched and mined
	Endpoints  []string // discovered API paths / route templates
	Params     []string // parameter names seen in fetch/axios/URLSearchParams usage
	GraphQL    []string // candidate GraphQL endpoints
	WebSockets []string // ws:// / wss:// endpoints referenced in JS
	SourceMaps []string // leaked .map source-map references
}

// Options tunes the harvest.
type Options struct {
	MaxScripts int           // cap the number of external scripts fetched (default 40)
	Timeout    time.Duration // per-request timeout (default 15s)
	Client     *http.Client  // optional; a scoped client should be passed by callers
	UserAgent  string
}

func (o *Options) defaults() {
	if o.MaxScripts == 0 {
		o.MaxScripts = 40
	}
	if o.Timeout == 0 {
		o.Timeout = 15 * time.Second
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: o.Timeout}
	}
	if o.UserAgent == "" {
		o.UserAgent = "DarkObscura/dynamic"
	}
}

var (
	// scriptSrcRe pulls <script src="..."> references out of HTML.
	scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	// pathRe finds quoted absolute-ish API paths inside JS/HTML. round-2: prefix
	// set doubled to catch more backend surfaces. The trailing (?:\?…)? clause
	// keeps query strings attached so parameterized endpoints (the valuable ones)
	// are not dropped at the '?'.
	pathRe = regexp.MustCompile(`["'` + "`" + `](/(?:api|v\d|graphql|rest|internal|admin|user|account|auth|gateway|oauth|token|session|billing|payment|order|cart|search|upload|download|export|import|webhook|callback|config|debug|metrics|health|swagger|openapi)[a-zA-Z0-9_\-/{}.:]*(?:\?[^"'` + "`" + `\s<>]{0,160})?)["'` + "`" + `]`)
	// absURLRe finds full http(s) URLs (same-origin filtering happens in mine).
	absURLRe = regexp.MustCompile(`https?://[A-Za-z0-9.\-]+(?::\d+)?/[A-Za-z0-9_\-./]*(?:\?[^"'` + "`" + `\s<>]{0,160})?`)
	// relAPIRe finds quoted relative API paths (fetch/axios without a leading slash).
	relAPIRe = regexp.MustCompile(`["'` + "`" + `]((?:api|v\d|graphql|rest|gateway)/[A-Za-z0-9_\-/.]{1,100}(?:\?[^"'` + "`" + `\s<>]{0,160})?)["'` + "`" + `]`)
	// mapRe finds source-map references (leaked maps expose original source).
	mapRe = regexp.MustCompile(`(?i)//[#@]\s*sourceMappingURL=([^\s'"]+\.map)`)
	// routeRe finds route templates like /users/:id or /orders/{orderId}.
	routeRe = regexp.MustCompile(`["'` + "`" + `](/[a-zA-Z0-9_\-/]*(?::[a-zA-Z]+|\{[a-zA-Z]+\})[a-zA-Z0-9_\-/{}:]*)["'` + "`" + `]`)
	// paramRe finds parameter names in common client-side idioms.
	paramRe = regexp.MustCompile(`(?:params\.|searchParams\.(?:get|set|append)\(|data\[|body\.)["']?([a-zA-Z_][a-zA-Z0-9_]{1,40})["']?`)
	// gqlRe finds GraphQL endpoints.
	gqlRe = regexp.MustCompile(`(?i)["'` + "`" + `]([a-z]*:?/?/?[^"'` + "`" + `]*graphql[a-zA-Z0-9_\-/]*)["'` + "`" + `]`)
	// wsRe finds websocket endpoints.
	wsRe = regexp.MustCompile(`(?i)(wss?://[a-zA-Z0-9_.:\-/]+)`)
)

// domProps are common DOM/JS property names that paramRe picks up as noise
// (e.g. from `element.innerHTML`); they are not real request parameters.
var domProps = map[string]bool{
	"innerhtml": true, "outerhtml": true, "textcontent": true, "innertext": true,
	"value": true, "length": true, "style": true, "classname": true, "id": true,
	"src": true, "href": true, "target": true, "parentnode": true, "children": true,
}

// Harvest fetches rawURL, follows its <script src> references, and mines the
// combined bodies for the dynamic attack surface.
func Harvest(ctx context.Context, rawURL string, opts Options) (*Surface, error) {
	opts.defaults()
	base, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	s := &Surface{Origin: base.Scheme + "://" + base.Host}

	pageBody, err := fetch(ctx, opts, rawURL)
	if err != nil {
		return nil, err
	}
	mine(s, pageBody)

	// Collect script URLs (same-origin first), fetch and mine each.
	seen := map[string]bool{}
	for _, m := range scriptSrcRe.FindAllStringSubmatch(pageBody, -1) {
		abs, err := base.Parse(m[1])
		if err != nil || seen[abs.String()] {
			continue
		}
		seen[abs.String()] = true
		if len(s.Scripts) >= opts.MaxScripts {
			break
		}
		if abs.Host != base.Host {
			continue // stay same-origin for safety
		}
		s.Scripts = append(s.Scripts, abs.String())
		if b, err := fetch(ctx, opts, abs.String()); err == nil {
			mine(s, b)
		}
	}

	dedupSort(&s.Endpoints)
	dedupSort(&s.Params)
	dedupSort(&s.GraphQL)
	dedupSort(&s.WebSockets)
	dedupSort(&s.SourceMaps)
	return s, nil
}

func fetch(ctx context.Context, opts Options, u string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", opts.UserAgent)
	resp, err := opts.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return string(body), nil
}

func mine(s *Surface, body string) {
	for _, m := range pathRe.FindAllStringSubmatch(body, -1) {
		s.Endpoints = append(s.Endpoints, m[1])
	}
	for _, m := range relAPIRe.FindAllStringSubmatch(body, -1) {
		s.Endpoints = append(s.Endpoints, "/"+strings.TrimPrefix(m[1], "/"))
	}
	for _, m := range absURLRe.FindAllString(body, -1) {
		// Keep only same-origin absolute URLs, reduced to path+query.
		if s.Origin != "" && strings.HasPrefix(m, s.Origin) {
			s.Endpoints = append(s.Endpoints, strings.TrimPrefix(m, s.Origin))
		}
	}
	for _, m := range routeRe.FindAllStringSubmatch(body, -1) {
		s.Endpoints = append(s.Endpoints, m[1])
	}
	for _, m := range paramRe.FindAllStringSubmatch(body, -1) {
		if !domProps[strings.ToLower(m[1])] {
			s.Params = append(s.Params, m[1])
		}
	}
	for _, m := range gqlRe.FindAllStringSubmatch(body, -1) {
		if strings.Contains(strings.ToLower(m[1]), "graphql") {
			s.GraphQL = append(s.GraphQL, m[1])
		}
	}
	for _, m := range wsRe.FindAllStringSubmatch(body, -1) {
		s.WebSockets = append(s.WebSockets, m[1])
	}
	for _, m := range mapRe.FindAllStringSubmatch(body, -1) {
		s.SourceMaps = append(s.SourceMaps, m[1])
	}
}

func dedupSort(list *[]string) {
	seen := map[string]bool{}
	var out []string
	for _, v := range *list {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	*list = out
}
