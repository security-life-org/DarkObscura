// Package access implements DarkObscura's broken-access-control engine: IDOR /
// BOLA detection by differential comparison across identities. Pattern-matching
// scanners cannot find IDOR because it is a logic flaw — you must actually ask
// "can user A read user B's object?" and compare the answers. access does that
// deterministically: it replays the same request under multiple identities
// (victim, attacker, anonymous) and confirms a finding only when a lower-
// privileged identity receives a response that is structurally equivalent to the
// authorized one. That reuses pkg/diff, the same zero-false-positive primitive
// behind the rest of the platform.
package access

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/security-life-org/DarkObscura/pkg/diff"
)

// Identity is a set of credentials applied to a request: header overrides and
// cookies. An empty Identity represents the anonymous / unauthenticated case.
type Identity struct {
	Name    string
	Headers map[string]string
	Cookies []*http.Cookie
}

// Target is one request to probe for horizontal access control. Owner is the
// identity legitimately allowed to access it (the baseline); the engine tests
// whether Others can reach the same resource.
type Target struct {
	Method string
	URL    string
	Body   string
}

// Finding is a confirmed access-control violation.
type Finding struct {
	Target       string
	Method       string
	Owner        string   // identity that is authorized
	Violator     string   // identity that should NOT have had access but did
	OwnerStatus  int
	ViolStatus   int
	Similarity   float64  // byte similarity between owner and violator responses
	Confirmed    bool
	Evidence     []string
}

// Engine performs multi-identity access-control testing.
type Engine struct {
	Client  *http.Client
	Timeout time.Duration
}

// New builds an Engine. If client is nil a default client is used.
func New(client *http.Client) *Engine {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return &Engine{Client: client, Timeout: 20 * time.Second}
}

type response struct {
	body   []byte
	status int
}

func (e *Engine) do(ctx context.Context, t Target, id Identity) (response, error) {
	var bodyReader io.Reader
	if t.Body != "" {
		bodyReader = stringReader(t.Body)
	}
	method := t.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, t.URL, bodyReader)
	if err != nil {
		return response{}, err
	}
	for k, v := range id.Headers {
		req.Header.Set(k, v)
	}
	for _, c := range id.Cookies {
		req.AddCookie(c)
	}
	resp, err := e.Client.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return response{body: b, status: resp.StatusCode}, nil
}

// Probe tests one target: owner is the authorized identity, others are the
// identities that must be denied. A finding fires only when an "other" identity
// gets a 2xx response that is structurally near-identical to the owner's — i.e.
// it actually read the protected object, not a generic error/redirect page.
func (e *Engine) Probe(ctx context.Context, t Target, owner Identity, others []Identity) (*Finding, error) {
	ownerResp, err := e.do(ctx, t, owner)
	if err != nil {
		return nil, err
	}
	if ownerResp.status < 200 || ownerResp.status >= 300 {
		// The owner itself can't read it; nothing meaningful to compare.
		return nil, nil
	}

	// Public-resource control: if an UNAUTHENTICATED request already returns the
	// same content, the resource is simply public — accessing it is not a broken
	// access-control finding. This eliminates the biggest IDOR false-positive
	// class (shared shells, public pages, generic error bodies).
	if pub, err := e.do(ctx, t, Identity{Name: "public-control"}); err == nil &&
		pub.status >= 200 && pub.status < 300 {
		if diff.Compare(ownerResp.body, ownerResp.status, pub.body, pub.status).ByteSimilarity >= 0.95 {
			return nil, nil // resource is public, not an authorization boundary
		}
	}

	for _, other := range others {
		if other.Name == "public-control" {
			continue
		}
		or, err := e.do(ctx, t, other)
		if err != nil {
			continue
		}
		if or.status < 200 || or.status >= 300 {
			continue // correctly denied
		}
		rep := diff.Compare(ownerResp.body, ownerResp.status, or.body, or.status)
		// Confirmed IDOR: the unauthorized identity got a 2xx whose body is
		// essentially the owner's protected content (high similarity, no
		// structural divergence).
		if rep.ByteSimilarity >= 0.95 && !rep.StructuralChange {
			return &Finding{
				Target: t.URL, Method: t.Method,
				Owner: owner.Name, Violator: other.Name,
				OwnerStatus: ownerResp.status, ViolStatus: or.status,
				Similarity: rep.ByteSimilarity, Confirmed: true,
				Evidence: []string{
					fmt.Sprintf("owner %q → HTTP %d (%d bytes)", owner.Name, ownerResp.status, len(ownerResp.body)),
					fmt.Sprintf("identity %q → HTTP %d (%d bytes), byteSim=%.3f struct-changed=%v",
						other.Name, or.status, len(or.body), rep.ByteSimilarity, rep.StructuralChange),
					"verified: an unauthorized identity received the owner's protected resource — IDOR / broken object-level authorization",
				},
			}, nil
		}
	}
	return nil, nil
}

// ProbeAll runs Probe across many targets and returns every confirmed finding.
func (e *Engine) ProbeAll(ctx context.Context, targets []Target, owner Identity, others []Identity) ([]Finding, error) {
	var out []Finding
	for _, t := range targets {
		f, err := e.Probe(ctx, t, owner, others)
		if err != nil {
			return out, err
		}
		if f != nil {
			out = append(out, *f)
		}
	}
	return out, nil
}

// stringReader avoids importing strings just for one reader.
type sr struct {
	s string
	i int
}

func stringReader(s string) io.Reader { return &sr{s: s} }

func (r *sr) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.i:])
	r.i += n
	return n, nil
}
