// Package crawl implements a bounded, same-origin spider that discovers the
// attack surface of a web application: linked pages, JavaScript-referenced
// endpoints, robots/sitemap entries, and — most importantly — URLs that carry
// parameters (links with query strings, GET and POST forms), which are the
// endpoints worth fuzzing.
package crawl

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// Endpoint mining regexes. Together they cover the ways a URL/path appears in a
// modern bundle: quoted absolute paths, full same-origin URLs, and quoted
// relative API paths (fetch/axios without a leading slash).
var (
	// pathRe: a quoted or backticked absolute path, optionally with a query.
	pathRe = regexp.MustCompile("[\"'`](/[A-Za-z0-9_][A-Za-z0-9_\\-./]{1,100}(?:\\?[^\"'`\\s<>]{0,160})?)[\"'`]")
	// absURLRe: a full http(s) URL (same-origin filtering happens later).
	absURLRe = regexp.MustCompile(`https?://[A-Za-z0-9.\-]+(?::\d+)?/[A-Za-z0-9_\-./]*(?:\?[^"'` + "`" + `\s<>]{0,160})?`)
	// relAPIRe: a quoted relative API-ish path (no leading slash).
	relAPIRe = regexp.MustCompile("[\"'`]((?:api|v\\d|graphql|rest|gateway)/[A-Za-z0-9_\\-./]{1,100}(?:\\?[^\"'`\\s<>]{0,160})?)[\"'`]")
	// sitemapLocRe: <loc> entries in sitemap.xml.
	sitemapLocRe = regexp.MustCompile(`(?i)<loc>\s*([^<\s]+)\s*</loc>`)
)

// linkAttrs maps HTML element names to the attributes that carry a URL. This is
// far broader than href/src: it captures resource links, media, framework
// bindings, and form-action overrides that all reveal endpoints.
var linkAttrs = map[string][]string{
	"a":      {"href", "data-href", "data-url", "ng-href", ":href", "hx-get", "hx-post", "to"},
	"area":   {"href"},
	"link":   {"href"},
	"iframe": {"src", "data-src"},
	"frame":  {"src"},
	"script": {"src"},
	"img":    {"src", "data-src"},
	"source": {"src", "srcset"},
	"video":  {"src", "poster"},
	"audio":  {"src"},
	"object": {"data"},
	"embed":  {"src"},
	"button": {"formaction"},
	"form":   {"action"},
}

// Result is the discovered surface.
type Result struct {
	Pages     []string // all reachable same-origin pages
	Endpoints []string // URLs carrying parameters (worth active scanning)
	Forms     []Form   // discovered forms
}

// Form is a discovered HTML form.
type Form struct {
	Action string   `json:"action"`
	Method string   `json:"method"`
	Inputs []string `json:"inputs"`
}

// Options bound the crawl.
type Options struct {
	MaxDepth int
	MaxPages int
	Client   *http.Client
}

// Crawl spiders startURL within its own origin and returns the discovered surface.
func Crawl(ctx context.Context, startURL string, opts Options) (Result, error) {
	if opts.MaxDepth == 0 {
		opts.MaxDepth = 3
	}
	if opts.MaxPages == 0 {
		opts.MaxPages = 80
	}
	client := opts.Client
	if client == nil {
		client = http.DefaultClient
	}

	start, err := url.Parse(startURL)
	if err != nil {
		return Result{}, err
	}
	origin := start.Scheme + "://" + start.Host

	seen := map[string]bool{}
	endpointSet := map[string]bool{}
	var res Result

	addEndpoint := func(u string) {
		if u != "" && !endpointSet[u] {
			endpointSet[u] = true
			res.Endpoints = append(res.Endpoints, u)
		}
	}

	type item struct {
		u     string
		depth int
	}
	queue := []item{{startURL, 0}}
	seen[normalize(startURL)] = true

	// Seed from robots.txt and sitemap.xml before spidering — cheap, high-yield.
	for _, s := range seedURLs(ctx, client, origin) {
		if sameOrigin(s, origin) && !seen[normalize(s)] {
			seen[normalize(s)] = true
			queue = append(queue, item{s, 1})
			if u2, err := url.Parse(s); err == nil && u2.RawQuery != "" {
				addEndpoint(s)
			}
		}
	}

	for len(queue) > 0 && len(res.Pages) < opts.MaxPages {
		cur := queue[0]
		queue = queue[1:]

		links, forms, err := fetchAndExtract(ctx, client, cur.u, origin)
		if err != nil {
			continue
		}
		res.Pages = append(res.Pages, cur.u)
		res.Forms = append(res.Forms, forms...)

		for _, f := range forms {
			for _, ep := range formEndpoints(cur.u, f) {
				addEndpoint(ep)
			}
		}
		for _, l := range links {
			if u2, err := url.Parse(l); err == nil && u2.RawQuery != "" {
				addEndpoint(l)
			}
			n := normalize(l)
			if !seen[n] && cur.depth < opts.MaxDepth {
				seen[n] = true
				queue = append(queue, item{l, cur.depth + 1})
			}
		}
	}
	return res, nil
}

// seedURLs fetches robots.txt and sitemap.xml and returns discovered paths/URLs.
func seedURLs(ctx context.Context, client *http.Client, origin string) []string {
	var out []string
	// robots.txt: harvest Allow/Disallow/Sitemap paths as discovery hints.
	if body := getBody(ctx, client, origin+"/robots.txt", 512<<10); body != "" {
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			low := strings.ToLower(line)
			switch {
			case strings.HasPrefix(low, "disallow:"), strings.HasPrefix(low, "allow:"):
				p := strings.TrimSpace(line[strings.IndexByte(line, ':')+1:])
				if p != "" && p != "/" && !strings.Contains(p, "*") {
					out = append(out, origin+ensureLeadingSlash(p))
				}
			case strings.HasPrefix(low, "sitemap:"):
				sm := strings.TrimSpace(line[strings.IndexByte(line, ':')+1:])
				out = append(out, harvestSitemap(ctx, client, sm)...)
			}
		}
	}
	// Default sitemap location.
	out = append(out, harvestSitemap(ctx, client, origin+"/sitemap.xml")...)
	return out
}

func harvestSitemap(ctx context.Context, client *http.Client, sitemapURL string) []string {
	body := getBody(ctx, client, sitemapURL, 2<<20)
	if body == "" {
		return nil
	}
	var out []string
	for _, m := range sitemapLocRe.FindAllStringSubmatch(body, -1) {
		out = append(out, strings.TrimSpace(m[1]))
	}
	return out
}

// fetchAndExtract downloads a page and returns same-origin links and forms.
func fetchAndExtract(ctx context.Context, client *http.Client, pageURL, origin string) (links []string, forms []Form, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "DarkObscura-Spider/0.2")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	text := string(body)
	base, _ := url.Parse(pageURL)
	ct := resp.Header.Get("Content-Type")

	// Regex-mine endpoints from ANY body (HTML inline JS, .js bundles, JSON) via
	// three complementary patterns: absolute paths, full URLs, relative API paths.
	links = append(links, mineBody(base, origin, text)...)

	// Only parse the DOM for HTML documents.
	isHTML := strings.Contains(ct, "html") || (ct == "" && looksLikeHTML(text))
	if !isHTML {
		return dedup(links), nil, nil
	}

	doc, err := html.Parse(strings.NewReader(text))
	if err != nil {
		return dedup(links), nil, err
	}

	var visit func(*html.Node)
	var curForm *Form
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode {
			if attrs, ok := linkAttrs[n.Data]; ok {
				for _, a := range attrs {
					if v, ok := attr(n, a); ok {
						for _, ref := range splitSrcset(a, v) {
							if abs := resolve(base, ref); abs != "" && sameOrigin(abs, origin) {
								links = append(links, abs)
							}
						}
					}
				}
			}
			switch n.Data {
			case "meta":
				// <meta http-equiv="refresh" content="0;url=/path">
				if strings.EqualFold(attrOr(n, "http-equiv", ""), "refresh") {
					if c, ok := attr(n, "content"); ok {
						if i := strings.Index(strings.ToLower(c), "url="); i >= 0 {
							if abs := resolve(base, strings.TrimSpace(c[i+4:])); abs != "" && sameOrigin(abs, origin) {
								links = append(links, abs)
							}
						}
					}
				}
			case "form":
				action, _ := attr(n, "action")
				method := strings.ToUpper(attrOr(n, "method", "GET"))
				f := Form{Action: resolve(base, action), Method: method}
				if f.Action == "" {
					f.Action = pageURL
				}
				curForm = &f
			case "input", "select", "textarea", "button":
				if curForm != nil {
					if name, ok := attr(n, "name"); ok && name != "" {
						curForm.Inputs = append(curForm.Inputs, name)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
		if n.Type == html.ElementNode && n.Data == "form" && curForm != nil {
			forms = append(forms, *curForm)
			curForm = nil
		}
	}
	visit(doc)
	return dedup(links), forms, nil
}

// mineBody applies the three endpoint regexes to a body and returns resolved,
// same-origin URLs.
func mineBody(base *url.URL, origin, text string) []string {
	var out []string
	push := func(ref string) {
		if abs := resolve(base, ref); abs != "" && sameOrigin(abs, origin) {
			out = append(out, abs)
		}
	}
	for _, m := range pathRe.FindAllStringSubmatch(text, -1) {
		push(m[1])
	}
	for _, m := range relAPIRe.FindAllStringSubmatch(text, -1) {
		push(m[1])
	}
	for _, m := range absURLRe.FindAllString(text, -1) {
		push(m)
	}
	return out
}

// formEndpoints turns a form into scannable URL(s) with its inputs as params.
// GET forms map directly to a query URL. POST forms are ALSO surfaced as a
// query-synthesized URL so the fuzzer can exercise their parameters (many
// endpoints accept the same params via GET); the verifier still gates every
// result, so this never manufactures a false positive.
func formEndpoints(pageURL string, f Form) []string {
	if len(f.Inputs) == 0 {
		return nil
	}
	action := f.Action
	if action == "" {
		action = pageURL
	}
	u, err := url.Parse(action)
	if err != nil {
		return nil
	}
	q := u.Query()
	for _, in := range f.Inputs {
		if in != "" && q.Get(in) == "" {
			q.Set(in, "1")
		}
	}
	u.RawQuery = q.Encode()
	return []string{u.String()}
}

func getBody(ctx context.Context, client *http.Client, u string, limit int64) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "DarkObscura-Spider/0.2")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	return string(b)
}

// splitSrcset expands a srcset attribute (comma-separated candidate URLs with
// optional descriptors) into individual URLs; other attributes pass through.
func splitSrcset(attrName, v string) []string {
	if attrName != "srcset" {
		return []string{v}
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) > 0 {
			out = append(out, fields[0])
		}
	}
	return out
}

func looksLikeHTML(s string) bool {
	low := strings.ToLower(s)
	return strings.Contains(low, "<html") || strings.Contains(low, "<!doctype html") || strings.Contains(low, "<body")
}

func ensureLeadingSlash(p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	return "/" + p
}

func attr(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val, true
		}
	}
	return "", false
}

func attrOr(n *html.Node, key, def string) string {
	if v, ok := attr(n, key); ok && v != "" {
		return v
	}
	return def
}

func resolve(base *url.URL, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "#") || strings.HasPrefix(ref, "javascript:") ||
		strings.HasPrefix(ref, "mailto:") || strings.HasPrefix(ref, "tel:") ||
		strings.HasPrefix(ref, "data:") || strings.HasPrefix(ref, "{{") {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(r)
	resolved.Fragment = ""
	return resolved.String()
}

func sameOrigin(u, origin string) bool {
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	return p.Scheme+"://"+p.Host == origin
}

// normalize strips the fragment for dedup.
func normalize(u string) string {
	if i := strings.IndexByte(u, '#'); i >= 0 {
		return u[:i]
	}
	return u
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
