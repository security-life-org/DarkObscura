// Package templates implements a lightweight, Nuclei-style templated check
// engine. Checks are declared in YAML (id, info, requests with matchers), so the
// tool's coverage can be extended without recompiling. Matchers are combined
// with AND/OR logic and can be negated, keeping checks precise.
package templates

import (
	"context"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Template is one declarative check. It is compatible with the community Nuclei
// template schema: both the legacy `requests:` block and the current `http:`
// block are accepted, `path` may be a scalar or a list, and the `{{BaseURL}}`
// placeholder is honored.
type Template struct {
	ID   string `yaml:"id"`
	Info struct {
		Name     string    `yaml:"name"`
		Severity string    `yaml:"severity"`
		Tags     flexString `yaml:"tags"`
	} `yaml:"info"`
	Requests []Request `yaml:"requests"`
	HTTP     []Request `yaml:"http"` // Nuclei v2.9+ renamed requests → http
	Flow     string    `yaml:"flow"` // multi-request orchestration (unsupported → reject)
}

// flexString accepts either a scalar (`tags: a,b`) or a YAML sequence
// (`tags: [a, b]`), both of which appear in official Nuclei templates.
type flexString string

func (f *flexString) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.SequenceNode {
		var arr []string
		if err := value.Decode(&arr); err != nil {
			return err
		}
		*f = flexString(strings.Join(arr, ","))
		return nil
	}
	*f = flexString(value.Value)
	return nil
}

// Compatible reports whether this template only uses features DarkObscura's
// engine supports (GET-able path requests with word/regex/status matchers).
// Templates using dsl/binary/size matchers, raw requests, or payload attacks are
// skipped rather than loaded as dead weight.
func (t Template) Compatible() bool {
	// Multi-request orchestration (`flow`, chained http blocks) implies
	// cross-request correlation and `internal` precondition matchers that this
	// single-shot engine cannot honor — running such a template's blocks
	// independently produces false positives. Accept only single-request
	// templates with reportable word/regex/status matchers.
	if t.Flow != "" {
		return false
	}
	reqs := t.allRequests()
	if len(reqs) != 1 {
		return false
	}
	r := reqs[0]
	if len(r.Path) == 0 || len(r.Matchers) == 0 {
		return false
	}
	for _, m := range r.Matchers {
		if m.Internal {
			return false // precondition-only matcher; not a standalone finding
		}
		switch m.Type {
		case "word", "regex", "status":
		default:
			return false
		}
	}
	return true
}

// allRequests merges the legacy and current request blocks.
func (t Template) allRequests() []Request {
	if len(t.HTTP) == 0 {
		return t.Requests
	}
	if len(t.Requests) == 0 {
		return t.HTTP
	}
	return append(append([]Request{}, t.Requests...), t.HTTP...)
}

// Request is an HTTP request plus the matchers that decide a hit.
type Request struct {
	Method       string            `yaml:"method"`
	Path         Paths             `yaml:"path"` // one or many paths; {{BaseURL}} supported
	Headers      map[string]string `yaml:"headers"`
	Body         string            `yaml:"body"`
	MatchersCond string            `yaml:"matchers-condition"` // and | or (default or)
	Matchers     []Matcher         `yaml:"matchers"`
}

// Paths accepts either a single scalar path or a YAML list of paths, matching
// Nuclei's schema where `path` is a list.
type Paths []string

// UnmarshalYAML handles both `path: /x` and `path: ["/x", "/y"]`.
func (p *Paths) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		*p = []string{value.Value}
		return nil
	}
	var arr []string
	if err := value.Decode(&arr); err != nil {
		return err
	}
	*p = arr
	return nil
}

// Matcher tests one aspect of the response.
type Matcher struct {
	Type      string   `yaml:"type"`      // word | regex | status
	Part      string   `yaml:"part"`      // body | header | all (default body)
	Words     []string `yaml:"words"`
	Regex     []string `yaml:"regex"`
	Status    []int    `yaml:"status"`
	Condition string   `yaml:"condition"` // and | or (default or) — within this matcher
	Negative  bool     `yaml:"negative"`
	Internal  bool     `yaml:"internal"` // precondition marker (never a finding on its own)
}

// Hit is a template match against a target.
type Hit struct {
	TemplateID string `json:"templateId"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	URL        string `json:"url"`
	Matched    string `json:"matched"`
}

// Engine runs templates against targets.
type Engine struct {
	templates []Template
	client    *http.Client
}

// New creates an engine with the given templates.
func New(tmpls []Template) *Engine {
	return &Engine{templates: tmpls, client: &http.Client{Timeout: 15 * time.Second}}
}

// Count returns how many templates are loaded.
func (e *Engine) Count() int { return len(e.templates) }

// LoadDir recursively parses every *.yaml/*.yml file under dir into templates,
// so it can be pointed straight at a cloned projectdiscovery/nuclei-templates
// tree. Files that fail to parse or use unsupported features are skipped (not
// fatal), keeping only templates this engine can actually evaluate.
func LoadDir(dir string) ([]Template, error) {
	var out []Template
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil // skip unreadable file
		}
		t, err := Parse(data)
		if err != nil || !t.Compatible() {
			return nil // skip unparseable / unsupported template
		}
		out = append(out, t)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Parse decodes a single YAML template.
func Parse(data []byte) (Template, error) {
	var t Template
	err := yaml.Unmarshal(data, &t)
	return t, err
}

// Run executes all templates against baseURL and returns any hits.
func (e *Engine) Run(ctx context.Context, baseURL string) ([]Hit, error) {
	var hits []Hit
	base := strings.TrimRight(baseURL, "/")
	for _, t := range e.templates {
		for _, req := range t.allRequests() {
			paths := req.Path
			if len(paths) == 0 {
				paths = Paths{""}
			}
			for _, p := range paths {
				hit, err := e.runRequest(ctx, base, t, req, p)
				if err != nil {
					continue
				}
				if hit != nil {
					hits = append(hits, *hit)
				}
			}
		}
	}
	return hits, nil
}

func (e *Engine) runRequest(ctx context.Context, base string, t Template, req Request, path string) (*Hit, error) {
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	// Honor Nuclei's {{BaseURL}} placeholder; otherwise append the path to base.
	var url string
	if strings.Contains(path, "{{BaseURL}}") {
		url = strings.ReplaceAll(path, "{{BaseURL}}", base)
	} else {
		url = base + path
	}
	var bodyR io.Reader
	if req.Body != "" {
		bodyR = strings.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, url, bodyR)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("User-Agent", "DarkObscura/0.1")
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	resp, err := e.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))

	matched, evidence := evalMatchers(req, resp, body)
	if matched {
		return &Hit{TemplateID: t.ID, Name: t.Info.Name, Severity: t.Info.Severity, URL: url, Matched: evidence}, nil
	}
	return nil, nil
}

// evalMatchers combines a request's matchers using its matchers-condition.
func evalMatchers(req Request, resp *http.Response, body []byte) (bool, string) {
	if len(req.Matchers) == 0 {
		return false, ""
	}
	andMode := strings.EqualFold(req.MatchersCond, "and")
	var evidences []string
	allOK := true
	anyOK := false
	for _, m := range req.Matchers {
		if m.Internal {
			continue // preconditions never contribute to a reportable hit
		}
		ok, ev := evalMatcher(m, resp, body)
		if m.Negative {
			ok = !ok
		}
		if ok {
			anyOK = true
			if ev != "" {
				evidences = append(evidences, ev)
			}
		} else {
			allOK = false
		}
	}
	hit := anyOK
	if andMode {
		hit = allOK
	}
	return hit, strings.Join(evidences, "; ")
}

func evalMatcher(m Matcher, resp *http.Response, body []byte) (bool, string) {
	part := m.Part
	if part == "" {
		part = "body"
	}
	hay := haystack(part, resp, body)
	switch m.Type {
	case "status":
		for _, s := range m.Status {
			if resp.StatusCode == s {
				return true, "status=" + itoa(s)
			}
		}
		return false, ""
	case "word":
		and := strings.EqualFold(m.Condition, "and")
		return matchAll(m.Words, and, func(w string) (bool, string) {
			if strings.Contains(hay, w) {
				return true, "word:" + w
			}
			return false, ""
		})
	case "regex":
		and := strings.EqualFold(m.Condition, "and")
		return matchAll(m.Regex, and, func(rx string) (bool, string) {
			re, err := regexp.Compile(rx)
			if err != nil {
				return false, ""
			}
			if loc := re.FindString(hay); loc != "" {
				return true, "regex:" + trunc(loc, 60)
			}
			return false, ""
		})
	}
	return false, ""
}

func matchAll(items []string, and bool, test func(string) (bool, string)) (bool, string) {
	var evs []string
	anyOK, allOK := false, true
	for _, it := range items {
		ok, ev := test(it)
		if ok {
			anyOK = true
			evs = append(evs, ev)
		} else {
			allOK = false
		}
	}
	hit := anyOK
	if and {
		hit = allOK
	}
	if hit {
		return true, strings.Join(evs, ",")
	}
	return false, ""
}

func haystack(part string, resp *http.Response, body []byte) string {
	switch part {
	case "header":
		var sb strings.Builder
		for k, vv := range resp.Header {
			for _, v := range vv {
				sb.WriteString(k + ": " + v + "\n")
			}
		}
		return sb.String()
	case "all":
		return headerString(resp) + string(body)
	default:
		return string(body)
	}
}

func headerString(resp *http.Response) string {
	var sb strings.Builder
	for k, vv := range resp.Header {
		for _, v := range vv {
			sb.WriteString(k + ": " + v + "\n")
		}
	}
	return sb.String()
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [12]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}
