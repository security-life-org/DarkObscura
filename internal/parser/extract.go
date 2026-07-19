package parser

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/net/html"
)

// Extractor discovers parameters from the parts of an HTTP flow. Parser scratch
// buffers are pooled to keep steady-state allocation low.
type Extractor struct {
	cls  *Classifier
	pool sync.Pool
}

// NewExtractor returns an Extractor using the given classifier (or the default
// if nil).
func NewExtractor(cls *Classifier) *Extractor {
	if cls == nil {
		cls = DefaultClassifier()
	}
	return &Extractor{
		cls:  cls,
		pool: sync.Pool{New: func() any { return new(bytes.Reader) }},
	}
}

// FromQuery extracts and classifies query-string parameters.
func (e *Extractor) FromQuery(rawQuery string) []Param {
	vals, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil
	}
	out := make([]Param, 0, len(vals))
	for k, vv := range vals {
		v := ""
		if len(vv) > 0 {
			v = vv[0]
		}
		out = append(out, Param{Name: k, Value: v, Location: "query"})
	}
	return e.cls.ClassifyParams(out)
}

// FromForm extracts application/x-www-form-urlencoded body parameters.
func (e *Extractor) FromForm(body []byte) []Param {
	return withLocation(e.FromQuery(string(body)), "body")
}

// FromJSON walks a JSON document and yields a param per leaf, with a dotted path
// as the name (e.g. "user.id", "items[0].sku").
func (e *Extractor) FromJSON(body []byte) []Param {
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil
	}
	var out []Param
	walkJSON("", root, &out)
	return e.cls.ClassifyParams(out)
}

func walkJSON(prefix string, v any, out *[]Param) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			walkJSON(key, child, out)
		}
	case []any:
		for i, child := range t {
			key := prefix + "[" + itoa(i) + "]"
			walkJSON(key, child, out)
		}
	default:
		*out = append(*out, Param{Name: prefix, Value: scalarString(v), Location: "json"})
	}
}

// FromHTML parses an HTML document and extracts form inputs and their names as
// parameters (surfacing hidden forms and hidden inputs).
func (e *Extractor) FromHTML(body []byte) []Param {
	r := e.pool.Get().(*bytes.Reader)
	r.Reset(body)
	defer e.pool.Put(r)

	doc, err := html.Parse(r)
	if err != nil {
		return nil
	}
	var out []Param
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "input", "textarea", "select":
				if name, ok := attr(n, "name"); ok {
					out = append(out, Param{Name: name, Value: attrOr(n, "value", ""), Location: "form"})
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
	}
	visit(doc)
	return e.cls.ClassifyParams(out)
}

func attr(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

func attrOr(n *html.Node, key, def string) string {
	if v, ok := attr(n, key); ok {
		return v
	}
	return def
}

func withLocation(ps []Param, loc string) []Param {
	for i := range ps {
		ps[i].Location = loc
	}
	return ps
}

func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		return strings.TrimRight(strings.TrimRight(ftoa(t), "0"), ".")
	default:
		return ""
	}
}
