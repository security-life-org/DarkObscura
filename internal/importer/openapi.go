// Package importer turns API specifications into scannable endpoints. It parses
// OpenAPI 3 / Swagger 2 JSON and expands every path + parameter into a concrete
// URL with sample values, so the whole documented API surface can be fuzzed.
package importer

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Endpoint is a scannable API endpoint derived from a spec.
type Endpoint struct {
	Method string   `json:"method"`
	URL    string   `json:"url"`
	Params []string `json:"params"`
}

// openAPISpec captures the subset of OpenAPI/Swagger we need.
type openAPISpec struct {
	Servers []struct {
		URL string `json:"url"`
	} `json:"servers"`
	Host     string `json:"host"`     // swagger 2
	BasePath string `json:"basePath"` // swagger 2
	Schemes  []string `json:"schemes"`
	Paths    map[string]map[string]operation `json:"paths"`
}

type operation struct {
	Parameters []struct {
		Name string `json:"name"`
		In   string `json:"in"` // query | path | header | ...
	} `json:"parameters"`
}

// ParseOpenAPI parses an OpenAPI/Swagger JSON document and returns concrete
// endpoints. baseOverride, if non-empty, replaces the server/base derived from
// the spec (useful when testing a deployment at a different host).
func ParseOpenAPI(doc []byte, baseOverride string) ([]Endpoint, error) {
	var spec openAPISpec
	if err := json.Unmarshal(doc, &spec); err != nil {
		return nil, fmt.Errorf("importer: parse spec: %w", err)
	}
	base := baseOverride
	if base == "" {
		base = deriveBase(spec)
	}
	base = strings.TrimRight(base, "/")

	var out []Endpoint
	for rawPath, ops := range spec.Paths {
		for method, op := range ops {
			m := strings.ToUpper(method)
			if m != "GET" && m != "POST" && m != "PUT" && m != "DELETE" && m != "PATCH" {
				continue // skip non-operation keys like "parameters"
			}
			ep := buildEndpoint(base, rawPath, m, op)
			out = append(out, ep)
		}
	}
	return out, nil
}

// deriveBase picks a base URL from OpenAPI servers or Swagger host/basePath.
func deriveBase(spec openAPISpec) string {
	if len(spec.Servers) > 0 && spec.Servers[0].URL != "" {
		return spec.Servers[0].URL
	}
	if spec.Host != "" {
		scheme := "https"
		for _, s := range spec.Schemes {
			if s == "http" {
				scheme = "http"
			}
		}
		return scheme + "://" + spec.Host + spec.BasePath
	}
	return ""
}

// buildEndpoint materializes a path template into a concrete URL: path params
// get a sample value, query params are appended with sample values.
func buildEndpoint(base, rawPath, method string, op operation) Endpoint {
	path := rawPath
	var params []string
	q := url.Values{}
	for _, p := range op.Parameters {
		switch p.In {
		case "path":
			path = strings.ReplaceAll(path, "{"+p.Name+"}", "1")
			params = append(params, p.Name)
		case "query":
			q.Set(p.Name, "1")
			params = append(params, p.Name)
		case "header":
			params = append(params, p.Name)
		}
	}
	full := base + path
	if enc := q.Encode(); enc != "" {
		full += "?" + enc
	}
	return Endpoint{Method: method, URL: full, Params: params}
}
