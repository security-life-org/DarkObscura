// Package harimport turns a recorded browser session (a HAR file exported from
// Chrome/Firefox DevTools) into a scannable surface: every parameterized
// endpoint the browser actually hit, plus the authentication material
// (Authorization bearer token, session cookies) captured along the way. This is
// the pragmatic, pure-Go form of "record auth in a real browser": drive the app
// by hand — including SPA routes, OAuth, and 2FA — export the HAR, and feed the
// result straight into authenticated scanning.
package harimport

import (
	"encoding/json"
	"sort"
	"strings"
)

// Result is the surface distilled from a HAR file.
type Result struct {
	Endpoints   []string // URLs that carry parameters (query or a form/JSON body)
	Hosts       []string // distinct hosts observed
	BearerToken string   // first Authorization: Bearer token seen
	Cookies     []string // distinct "name=value" cookies seen on requests
	Requests    int      // total request entries parsed
}

// har mirrors the subset of the HAR 1.2 schema we consume.
type har struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method  string `json:"method"`
				URL     string `json:"url"`
				Headers []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"headers"`
				QueryString []struct {
					Name string `json:"name"`
				} `json:"queryString"`
				PostData struct {
					Text   string `json:"text"`
					Params []struct {
						Name string `json:"name"`
					} `json:"params"`
				} `json:"postData"`
			} `json:"request"`
		} `json:"entries"`
	} `json:"log"`
}

// Parse reads a HAR document and extracts the scannable surface.
func Parse(data []byte) (Result, error) {
	var h har
	if err := json.Unmarshal(data, &h); err != nil {
		return Result{}, err
	}
	var res Result
	endpointSet := map[string]bool{}
	hostSet := map[string]bool{}
	cookieSet := map[string]bool{}

	for _, e := range h.Log.Entries {
		req := e.Request
		res.Requests++
		if host := hostOf(req.URL); host != "" {
			hostSet[host] = true
		}
		// A request is a scannable endpoint if it carries query params or a body.
		hasParams := len(req.QueryString) > 0 || strings.Contains(req.URL, "?") ||
			len(req.PostData.Params) > 0 || req.PostData.Text != ""
		if hasParams && !endpointSet[req.URL] {
			endpointSet[req.URL] = true
			res.Endpoints = append(res.Endpoints, req.URL)
		}
		for _, hd := range req.Headers {
			switch strings.ToLower(hd.Name) {
			case "authorization":
				if res.BearerToken == "" && strings.HasPrefix(strings.ToLower(hd.Value), "bearer ") {
					res.BearerToken = strings.TrimSpace(hd.Value[len("bearer "):])
				}
			case "cookie":
				for _, c := range strings.Split(hd.Value, ";") {
					if c = strings.TrimSpace(c); c != "" {
						cookieSet[c] = true
					}
				}
			}
		}
	}
	for h := range hostSet {
		res.Hosts = append(res.Hosts, h)
	}
	for c := range cookieSet {
		res.Cookies = append(res.Cookies, c)
	}
	sort.Strings(res.Endpoints)
	sort.Strings(res.Hosts)
	sort.Strings(res.Cookies)
	return res, nil
}

// CookieHeader returns the captured cookies joined into a single Cookie header
// value, suitable for authsession/access identity headers.
func (r Result) CookieHeader() string {
	return strings.Join(r.Cookies, "; ")
}

func hostOf(rawURL string) string {
	s := rawURL
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return s
}
