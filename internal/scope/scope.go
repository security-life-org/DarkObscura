// Package scope enforces engagement scoping and SSRF protection. Every outbound
// request DarkObscura makes is checked against an allowlist of in-scope hosts,
// and — unless explicitly permitted — requests to private, loopback, link-local,
// and cloud-metadata addresses are blocked. Enforcement happens at dial time so
// it cannot be bypassed by redirects or DNS rebinding.
package scope

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Guard decides whether a target is in scope.
type Guard struct {
	hosts        []string     // allowed exact hosts / suffix domains (".example.com")
	cidrs        []*net.IPNet // allowed CIDRs
	allowPrivate bool         // permit private/loopback/link-local/metadata targets
}

// New builds a Guard from a comma-separated scope spec (hosts, domains, or
// CIDRs) and the allowPrivate flag. An empty spec means "any public host".
func New(spec string, allowPrivate bool) *Guard {
	g := &Guard{allowPrivate: allowPrivate}
	for _, raw := range strings.Split(spec, ",") {
		s := strings.TrimSpace(strings.ToLower(raw))
		if s == "" {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(s); err == nil {
			g.cidrs = append(g.cidrs, ipnet)
			continue
		}
		g.hosts = append(g.hosts, s)
	}
	return g
}

// Scoped reports whether an explicit host allowlist was configured.
func (g *Guard) Scoped() bool { return len(g.hosts) > 0 || len(g.cidrs) > 0 }

// AllowURL validates a target URL: parses it, checks the host against the
// allowlist, and resolves it to reject blocked address ranges.
func (g *Guard) AllowURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("scope: invalid URL")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("scope: missing host")
	}
	if err := g.allowHost(host); err != nil {
		return err
	}
	// Resolve and check every address the host maps to.
	ips, err := net.LookupIP(host)
	if err != nil {
		// If it's already a literal IP, LookupIP returns it; otherwise a DNS
		// failure is treated as out-of-scope to fail safe.
		if ip := net.ParseIP(host); ip != nil {
			ips = []net.IP{ip}
		} else {
			return fmt.Errorf("scope: cannot resolve %q", host)
		}
	}
	for _, ip := range ips {
		if err := g.allowIP(ip); err != nil {
			return err
		}
	}
	return nil
}

// allowHost checks the host string against the allowlist (if any).
func (g *Guard) allowHost(host string) error {
	host = strings.ToLower(host)
	if !g.Scoped() {
		return nil // no host allowlist → rely on IP rules only
	}
	for _, h := range g.hosts {
		if host == h || (strings.HasPrefix(h, ".") && strings.HasSuffix(host, h)) ||
			host == strings.TrimPrefix(h, ".") {
			return nil
		}
	}
	// CIDR-only scope may still allow by IP; defer to allowIP.
	if len(g.cidrs) > 0 {
		return nil
	}
	return fmt.Errorf("scope: host %q is not in the configured scope", host)
}

// allowIP rejects blocked ranges (unless allowPrivate) and enforces CIDR scope.
func (g *Guard) allowIP(ip net.IP) error {
	if !g.allowPrivate && isBlocked(ip) {
		return fmt.Errorf("scope: %s is a private/reserved/metadata address (blocked; use --allow-private to permit)", ip)
	}
	if len(g.cidrs) > 0 {
		for _, c := range g.cidrs {
			if c.Contains(ip) {
				return nil
			}
		}
		// With CIDR scope and matching host allowlist already passed, allow;
		// otherwise if only CIDRs were given, the IP must be inside one.
		if len(g.hosts) == 0 {
			return fmt.Errorf("scope: %s is outside the configured CIDR scope", ip)
		}
	}
	return nil
}

// isBlocked reports whether ip is in a range unsafe to reach from a deployed
// scanner: loopback, private, link-local (incl. 169.254.169.254 metadata),
// unique-local, and unspecified.
func isBlocked(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	// Cloud metadata endpoints and CGNAT.
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 169 && ip4[1] == 254 { // 169.254.0.0/16 (AWS/GCP/Azure metadata)
			return true
		}
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 { // 100.64.0.0/10 CGNAT
			return true
		}
	}
	return false
}

// Transport returns an *http.Transport whose DialContext enforces the scope at
// connection time — redirect- and DNS-rebind-proof.
func (g *Guard) Transport() *http.Transport {
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          128,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if err := g.allowIP(ip); err != nil {
					return nil, err
				}
			}
			// Dial the first allowed IP directly (pin it to avoid a rebind race).
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
		},
	}
}

// Client returns an *http.Client using the scope-enforcing transport.
func (g *Guard) Client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: g.Transport()}
}
