// Package sourcemap reconstructs a web app's original source from a leaked
// JavaScript source map (.map). Production bundles frequently ship a
// sourceMappingURL pointing at a .map that embeds the full pre-minification
// source in `sourcesContent`. Recovering it exposes internal endpoints,
// comments, and hard-coded secrets that the minified bundle hides. This package
// parses the map, reconstructs each original file, and scans the recovered code
// for secrets (via internal/secrets) and referenced endpoints.
package sourcemap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/security-life-org/DarkObscura/internal/secrets"
)

// Source is one reconstructed original file.
type Source struct {
	Path    string
	Content string
}

// Result is the outcome of reconstructing and scanning a source map.
type Result struct {
	Sources   []Source
	Secrets   []secrets.Match
	Endpoints []string
}

// sourceMap mirrors the Source Map v3 schema fields we use.
type sourceMap struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

var (
	mapURLRe  = regexp.MustCompile(`(?i)//[#@]\s*sourceMappingURL=([^\s'"]+)`)
	endpointRe = regexp.MustCompile(`["'` + "`" + `](/(?:api|v\d|graphql|rest|internal|admin|auth|gateway|user|account)[A-Za-z0-9_\-/.{}]*(?:\?[^"'` + "`" + `\s<>]{0,160})?)["'` + "`" + `]`)
)

// Parse reconstructs sources from raw .map bytes and scans them.
func Parse(data []byte) (*Result, error) {
	var sm sourceMap
	if err := json.Unmarshal(data, &sm); err != nil {
		return nil, err
	}
	res := &Result{}
	epSet := map[string]bool{}
	for i, content := range sm.SourcesContent {
		if content == "" {
			continue
		}
		path := "unknown"
		if i < len(sm.Sources) {
			path = sm.Sources[i]
		}
		res.Sources = append(res.Sources, Source{Path: path, Content: content})
		res.Secrets = append(res.Secrets, secrets.Scan([]byte(content))...)
		for _, m := range endpointRe.FindAllStringSubmatch(content, -1) {
			if !epSet[m[1]] {
				epSet[m[1]] = true
				res.Endpoints = append(res.Endpoints, m[1])
			}
		}
	}
	sort.Strings(res.Endpoints)
	return res, nil
}

// FetchAndReconstruct fetches a .map URL directly, or — if given a .js URL —
// discovers its sourceMappingURL and fetches that. It then reconstructs+scans.
func FetchAndReconstruct(ctx context.Context, client *http.Client, jsOrMapURL string) (*Result, error) {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	mapURL := jsOrMapURL
	if !strings.HasSuffix(strings.Split(jsOrMapURL, "?")[0], ".map") {
		// Fetch the JS and look for its sourceMappingURL.
		js, err := fetch(ctx, client, jsOrMapURL)
		if err != nil {
			return nil, err
		}
		m := mapURLRe.FindStringSubmatch(js)
		if m == nil {
			return &Result{}, nil // no source map referenced
		}
		ref := strings.TrimSpace(m[1])
		if strings.HasPrefix(ref, "data:") {
			return parseDataURL(ref)
		}
		mapURL = resolveRef(jsOrMapURL, ref)
	}
	data, err := fetch(ctx, client, mapURL)
	if err != nil {
		return nil, err
	}
	return Parse([]byte(data))
}

func parseDataURL(ref string) (*Result, error) {
	// data:application/json;base64,<...> or plain
	i := strings.Index(ref, ",")
	if i < 0 {
		return &Result{}, nil
	}
	payload := ref[i+1:]
	if strings.Contains(ref[:i], "base64") {
		dec, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return nil, err
		}
		return Parse(dec)
	}
	return Parse([]byte(payload))
}

func fetch(ctx context.Context, client *http.Client, u string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "DarkObscura/sourcemap")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	return string(b), nil
}

// resolveRef resolves a (possibly relative) source-map reference against the JS
// URL's directory.
func resolveRef(jsURL, ref string) string {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	base := jsURL
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[:i+1]
	}
	return base + ref
}
