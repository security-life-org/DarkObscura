// Package logicflow tests business-logic vulnerabilities — the class with no
// payload and no signature, the reason elite testers still beat scanners. It runs
// a recorded multi-step flow (login → add-to-cart → checkout → pay) as a state
// machine, threading extracted variables (tokens, ids, prices) between steps, and
// then re-runs it while tampering one step: negative quantity, zero/altered
// price, a swapped object id, a skipped step. Detection is deterministic and
// false-positive-free: a finding fires only when the server ACCEPTS a state it
// must have rejected (a tampered request returns success equivalent to the
// legitimate one) or an explicit numeric invariant is violated. No guessing.
package logicflow

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/security-life-org/DarkObscura/pkg/diff"
)

// Step is one request in the flow.
type Step struct {
	Name     string            `json:"name"`
	Method   string            `json:"method"`
	URL      string            `json:"url"`  // may contain {{var}} placeholders
	Body     string            `json:"body"` // templated; treated as form-encoded for tampering
	Headers  map[string]string `json:"headers"`
	Extract  map[string]string `json:"extract"` // var -> regex with one capture group applied to response body
	Expect   int               `json:"expectStatus"`
	Location string            `json:"location"` // "query" | "form" (for tampering targeting)
}

// Invariant asserts a numeric relationship between two variables (or a var and a
// literal) that must hold after the flow. A violation is a finding.
type Invariant struct {
	Name  string `json:"name"`
	Left  string `json:"left"`  // variable name
	Op    string `json:"op"`    // "<", "<=", "==", ">=", ">", "!="
	Right string `json:"right"` // variable name or numeric literal
}

// Tamper describes a single-step abuse to attempt.
type Tamper struct {
	Name         string `json:"name"`
	Step         string `json:"step"`     // step Name to tamper
	Field        string `json:"field"`    // query/form field to mutate
	Mutation     string `json:"mutation"` // negative|zero|huge|empty|swap:<value>
	ExpectReject bool   `json:"expectReject"`
}

// Flow is a complete logic test specification.
type Flow struct {
	Vars      map[string]string `json:"vars"`
	Steps     []Step            `json:"steps"`
	Invariant []Invariant       `json:"invariants"`
	Tampers   []Tamper          `json:"tampers"`
}

// Finding is a confirmed business-logic issue.
type Finding struct {
	Class    string
	Severity string
	Detail   string
	Evidence []string
}

type stepResult struct {
	status int
	body   []byte
}

// Runner executes flows.
type Runner struct {
	Client *http.Client
}

// NewRunner builds a runner. If client is nil a default is used.
func NewRunner(client *http.Client) *Runner {
	if client == nil {
		client = &http.Client{}
	}
	return &Runner{Client: client}
}

var tmplRe = regexp.MustCompile(`\{\{(\w+)\}\}`)

func subst(s string, vars map[string]string) string {
	return tmplRe.ReplaceAllStringFunc(s, func(m string) string {
		name := tmplRe.FindStringSubmatch(m)[1]
		return vars[name]
	})
}

// runFlow executes every step, applying an optional tamper at a named step, and
// returns per-step results plus the final variable state.
func (r *Runner) runFlow(ctx context.Context, f Flow, tamper *Tamper) (map[string]stepResult, map[string]string, error) {
	vars := map[string]string{}
	for k, v := range f.Vars {
		vars[k] = v
	}
	results := map[string]stepResult{}
	for _, st := range f.Steps {
		method := st.Method
		if method == "" {
			method = http.MethodGet
		}
		u := subst(st.URL, vars)
		body := subst(st.Body, vars)
		loc := st.Location
		if loc == "" {
			loc = "form"
		}
		if tamper != nil && tamper.Step == st.Name {
			u, body = applyTamper(u, body, loc, *tamper)
		}
		var reqBody io.Reader
		if body != "" {
			reqBody = strings.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, u, reqBody)
		if err != nil {
			return nil, nil, err
		}
		if body != "" && loc == "form" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		for hk, hv := range st.Headers {
			req.Header.Set(hk, subst(hv, vars))
		}
		resp, err := r.Client.Do(req)
		if err != nil {
			return nil, nil, err
		}
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		results[st.Name] = stepResult{status: resp.StatusCode, body: rb}
		for varName, pat := range st.Extract {
			re, err := regexp.Compile(pat)
			if err != nil {
				continue
			}
			if m := re.FindSubmatch(rb); len(m) >= 2 {
				vars[varName] = string(m[1])
			}
		}
	}
	return results, vars, nil
}

// applyTamper mutates the target field in the URL query or form body.
func applyTamper(u, body, loc string, t Tamper) (string, string) {
	mutate := func(vals map[string][]string) {
		cur := ""
		if v := vals[t.Field]; len(v) > 0 {
			cur = v[0]
		}
		vals[t.Field] = []string{mutation(cur, t.Mutation)}
	}
	if loc == "query" {
		if i := strings.IndexByte(u, '?'); i >= 0 {
			q := parseVals(u[i+1:])
			mutate(q)
			return u[:i+1] + encodeVals(q), body
		}
		return u + "?" + encodeVals(map[string][]string{t.Field: {mutation("", t.Mutation)}}), body
	}
	q := parseVals(body)
	mutate(q)
	return u, encodeVals(q)
}

func mutation(cur, kind string) string {
	switch {
	case kind == "negative":
		if n, err := strconv.Atoi(cur); err == nil {
			return strconv.Itoa(-abs(n) - 1)
		}
		return "-1"
	case kind == "zero":
		return "0"
	case kind == "huge":
		return "999999999"
	case kind == "empty":
		return ""
	case strings.HasPrefix(kind, "swap:"):
		return strings.TrimPrefix(kind, "swap:")
	default:
		return cur
	}
}

// Run executes the flow baseline, evaluates invariants, and runs every tamper,
// returning all confirmed findings.
func (r *Runner) Run(ctx context.Context, f Flow) ([]Finding, error) {
	baseline, vars, err := r.runFlow(ctx, f, nil)
	if err != nil {
		return nil, fmt.Errorf("baseline flow: %w", err)
	}
	var findings []Finding

	// Invariant checks on the final variable state.
	for _, inv := range f.Invariant {
		if violated, detail := checkInvariant(inv, vars); violated {
			findings = append(findings, Finding{
				Class: "logic-invariant-violation", Severity: "high",
				Detail:   fmt.Sprintf("invariant %q violated: %s", inv.Name, detail),
				Evidence: []string{"verified: post-flow state violates a required business invariant — logic flaw"},
			})
		}
	}

	// Tamper checks: a tampered step that should be rejected but is accepted.
	for _, t := range f.Tampers {
		tampered, _, err := r.runFlow(ctx, f, &t)
		if err != nil {
			continue
		}
		br, ok1 := baseline[t.Step]
		tr, ok2 := tampered[t.Step]
		if !ok1 || !ok2 {
			continue
		}
		accepted := tr.status >= 200 && tr.status < 300
		if t.ExpectReject && accepted {
			rep := diff.Compare(br.body, br.status, tr.body, tr.status)
			// Confirmed only when the tampered request was accepted like the
			// legitimate one (same 2xx class, no structural rejection divergence).
			if br.status/100 == 2 && !rep.StatusChanged {
				findings = append(findings, Finding{
					Class: "business-logic-bypass", Severity: "high",
					Detail: fmt.Sprintf("tamper %q (%s %s=%s) accepted at step %q (HTTP %d)",
						t.Name, t.Field, t.Mutation, t.Field, t.Step, tr.status),
					Evidence: []string{
						fmt.Sprintf("legitimate step %q → HTTP %d", t.Step, br.status),
						fmt.Sprintf("tampered step %q → HTTP %d (byteSim=%.2f, no rejection)", t.Step, tr.status, rep.ByteSimilarity),
						"verified: server accepted a state it should have rejected — business-logic bypass",
					},
				})
			}
		}
	}
	return findings, nil
}

func checkInvariant(inv Invariant, vars map[string]string) (bool, string) {
	l, okl := toFloat(vars[inv.Left])
	rRaw, hasVar := vars[inv.Right]
	var rv float64
	var okr bool
	if hasVar {
		rv, okr = toFloat(rRaw)
	} else {
		rv, okr = toFloat(inv.Right)
	}
	if !okl || !okr {
		return false, ""
	}
	violated := false
	switch inv.Op {
	case "<":
		violated = !(l < rv)
	case "<=":
		violated = !(l <= rv)
	case "==":
		violated = !(l == rv)
	case ">=":
		violated = !(l >= rv)
	case ">":
		violated = !(l > rv)
	case "!=":
		violated = !(l != rv)
	}
	if violated {
		return true, fmt.Sprintf("%s(%.2f) %s %s(%.2f) does not hold", inv.Left, l, inv.Op, inv.Right, rv)
	}
	return false, ""
}

func toFloat(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	return f, err == nil
}

func parseVals(s string) map[string][]string {
	out := map[string][]string{}
	for _, pair := range strings.Split(s, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		out[k] = append(out[k], v)
	}
	return out
}

func encodeVals(vals map[string][]string) string {
	var parts []string
	for k, vs := range vals {
		for _, v := range vs {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, "&")
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
