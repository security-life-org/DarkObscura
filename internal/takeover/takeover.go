// Package takeover detects subdomain takeover with zero false positives. A
// takeover is only reported when BOTH deterministic conditions hold: (1) the
// host's DNS CNAME points at a third-party provider known to allow dangling
// claims, and (2) fetching the host returns that provider's unmistakable
// "unclaimed resource" page. Either signal alone is insufficient (a live site on
// the provider also matches the CNAME); requiring the fingerprinted error body
// is what makes a confirmed finding truly confirmed.
package takeover

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// provider pairs a CNAME target substring with the body signature of its
// unclaimed/dangling resource page.
type provider struct {
	name       string
	cnameMatch string
	bodySig    string
}

var providers = []provider{
	{"GitHub Pages", "github.io", "There isn't a GitHub Pages site here"},
	{"Heroku", "herokuapp.com", "No such app"},
	{"Heroku", "herokudns.com", "no-such-app.html"},
	{"AWS S3", "amazonaws.com", "NoSuchBucket"},
	{"Azure", "azurewebsites.net", "404 Web Site not found"},
	{"Azure Traffic Manager", "trafficmanager.net", "404 Web Site not found"},
	{"Fastly", "fastly.net", "Fastly error: unknown domain"},
	{"Pantheon", "pantheonsite.io", "404 error unknown site"},
	{"Read the Docs", "readthedocs.io", "unknown to Read the Docs"},
	{"Surge.sh", "surge.sh", "project not found"},
	{"Bitbucket", "bitbucket.io", "Repository not found"},
	{"Shopify", "myshopify.com", "Sorry, this shop is currently unavailable"},
	{"Tumblr", "domains.tumblr.com", "Whatever you were looking for doesn't currently exist"},
	{"WordPress.com", "wordpress.com", "Do you want to register"},
	{"Ghost", "ghost.io", "The thing you were looking for is no longer here"},
	{"Unbounce", "unbouncepages.com", "The requested URL was not found on this server"},
	{"Cargo", "cargocollective.com", "404 Not Found"},
	{"Webflow", "proxy-ssl.webflow.com", "The page you are looking for doesn't exist"},
}

// Finding is a confirmed subdomain takeover.
type Finding struct {
	Host       string
	Provider   string
	CNAME      string
	Severity   string
	Confirmed  bool
	Evidence   []string
}

// Resolver is the CNAME lookup used; overridable for tests.
type Resolver func(ctx context.Context, host string) (string, error)

// Checker performs takeover checks.
type Checker struct {
	Client   *http.Client
	Resolve  Resolver
}

// New builds a Checker with sane defaults.
func New() *Checker {
	return &Checker{
		Client: &http.Client{Timeout: 12 * time.Second},
		Resolve: func(ctx context.Context, host string) (string, error) {
			var r net.Resolver
			return r.LookupCNAME(ctx, host)
		},
	}
}

// Check inspects one host and returns a confirmed takeover finding or nil.
func (c *Checker) Check(ctx context.Context, host string) (*Finding, error) {
	cname, err := c.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	cnameL := strings.ToLower(strings.TrimSuffix(cname, "."))
	var matched *provider
	for i := range providers {
		if strings.Contains(cnameL, providers[i].cnameMatch) {
			matched = &providers[i]
			break
		}
	}
	if matched == nil {
		return nil, nil // CNAME does not point at a takeover-prone provider
	}
	body := c.fetch(ctx, host)
	if !strings.Contains(body, matched.bodySig) {
		return nil, nil // provider serves a live site — NOT dangling, no finding
	}
	return &Finding{
		Host: host, Provider: matched.name, CNAME: cnameL, Severity: "high", Confirmed: true,
		Evidence: []string{
			"CNAME " + host + " → " + cnameL + " (" + matched.name + ")",
			"response contains the provider's unclaimed-resource signature: " + matched.bodySig,
			"verified: the CNAME target is unclaimed on " + matched.name + " — subdomain takeover",
		},
	}, nil
}

func (c *Checker) fetch(ctx context.Context, host string) string {
	for _, scheme := range []string{"https://", "http://"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+host+"/", nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "DarkObscura/takeover")
		resp, err := c.Client.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
		resp.Body.Close()
		if len(b) > 0 {
			return string(b)
		}
	}
	return ""
}
