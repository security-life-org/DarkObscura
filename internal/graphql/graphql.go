// Package graphql implements DarkObscura's GraphQL attack module. GraphQL APIs
// are largely invisible to classic scanners (one endpoint, POST bodies, a typed
// schema) yet concentrate high-value bugs: exposed introspection, missing
// field-level authorization, batching/alias abuse that defeats rate limits, and
// injection inside arguments. This module runs the introspection query, parses
// the returned type system, enumerates the query/mutation surface, and produces
// concrete abuse probes — all with net/http + encoding/json.
package graphql

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to a single GraphQL endpoint.
type Client struct {
	Endpoint string
	HTTP     *http.Client
	Headers  map[string]string
}

// NewClient builds a GraphQL client. If httpClient is nil a default is used.
func NewClient(endpoint string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}
	return &Client{Endpoint: endpoint, HTTP: httpClient, Headers: map[string]string{}}
}

// introspectionQuery is a compact schema-dump query.
const introspectionQuery = `{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind fields { name args { name } } } } }"}`

// Field is one field on the query/mutation root.
type Field struct {
	Name string
	Args []string
}

// Schema is the parsed, security-relevant slice of a GraphQL schema.
type Schema struct {
	QueryType    string
	MutationType string
	Queries      []Field
	Mutations    []Field
	TypeCount    int
}

// Finding is a confirmed GraphQL security issue.
type Finding struct {
	Class    string
	Severity string
	Detail   string
	Evidence []string
}

func (c *Client) post(ctx context.Context, jsonBody string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, strings.NewReader(jsonBody))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return b, resp.StatusCode, nil
}

// Introspect runs the introspection query and parses the schema. A non-nil
// Schema with a populated type list is itself a finding (introspection enabled).
func (c *Client) Introspect(ctx context.Context) (*Schema, error) {
	body, status, err := c.post(ctx, introspectionQuery)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, fmt.Errorf("introspection HTTP %d", status)
	}
	var raw struct {
		Data struct {
			Schema struct {
				QueryType    struct{ Name string } `json:"queryType"`
				MutationType struct{ Name string } `json:"mutationType"`
				Types        []struct {
					Name   string
					Kind   string
					Fields []struct {
						Name string
						Args []struct{ Name string }
					}
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse introspection: %w", err)
	}
	sc := raw.Data.Schema
	s := &Schema{
		QueryType:    sc.QueryType.Name,
		MutationType: sc.MutationType.Name,
		TypeCount:    len(sc.Types),
	}
	for _, t := range sc.Types {
		if t.Name == sc.QueryType.Name || t.Name == sc.MutationType.Name {
			var fields []Field
			for _, f := range t.Fields {
				var args []string
				for _, a := range f.Args {
					args = append(args, a.Name)
				}
				fields = append(fields, Field{Name: f.Name, Args: args})
			}
			if t.Name == sc.QueryType.Name {
				s.Queries = fields
			} else {
				s.Mutations = fields
			}
		}
	}
	return s, nil
}

// Audit runs the introspection-based checks and the alias/batching abuse probe,
// returning confirmed findings.
func (c *Client) Audit(ctx context.Context) ([]Finding, error) {
	var findings []Finding
	s, err := c.Introspect(ctx)
	if err == nil && s.TypeCount > 0 {
		findings = append(findings, Finding{
			Class: "graphql-introspection", Severity: "medium",
			Detail: fmt.Sprintf("introspection enabled: %d types, %d queries, %d mutations",
				s.TypeCount, len(s.Queries), len(s.Mutations)),
			Evidence: []string{
				"verified: __schema introspection returned the full type system — attackers can map the entire API",
				fmt.Sprintf("queryType=%s mutationType=%s", s.QueryType, s.MutationType),
			},
		})
		if dangerous := dangerousMutations(s.Mutations); len(dangerous) > 0 {
			findings = append(findings, Finding{
				Class: "graphql-dangerous-mutations", Severity: "high",
				Detail: fmt.Sprintf("%d state-changing mutation(s) exposed via introspection: %s",
					len(dangerous), strings.Join(dangerous, ", ")),
				Evidence: []string{
					"these mutations can create/delete/modify data — verify each enforces authorization",
					"attackers who map them via introspection will probe for missing access control",
				},
			})
		}
	}
	if af := c.checkAliasAbuse(ctx); af != nil {
		findings = append(findings, *af)
	}
	if sf := c.checkFieldSuggestion(ctx); sf != nil {
		findings = append(findings, *sf)
	}
	return findings, nil
}

// dangerousMutations returns the names of mutations whose verb implies a
// sensitive state change (create/update/delete/grant/etc.).
func dangerousMutations(muts []Field) []string {
	verbs := []string{"delete", "remove", "drop", "update", "create", "add", "set", "grant", "revoke", "reset", "change", "admin", "promote", "disable", "enable"}
	var out []string
	for _, m := range muts {
		low := strings.ToLower(m.Name)
		for _, v := range verbs {
			if strings.Contains(low, v) {
				out = append(out, m.Name)
				break
			}
		}
	}
	return out
}

// checkFieldSuggestion detects schema leakage even when introspection is
// disabled: many GraphQL servers answer an unknown field with a "Did you mean
// …?" suggestion, disclosing real field names one guess at a time.
func (c *Client) checkFieldSuggestion(ctx context.Context) *Finding {
	body, _, err := c.post(ctx, `{"query":"{ __dobscura_nonexistent_field__ }"}`)
	if err != nil {
		return nil
	}
	low := strings.ToLower(string(body))
	if strings.Contains(low, "did you mean") {
		return &Finding{
			Class: "graphql-field-suggestion", Severity: "medium",
			Detail: "server returns field-name suggestions on invalid queries",
			Evidence: []string{
				"invalid field triggered a \"Did you mean\" suggestion",
				"verified: schema is enumerable via error suggestions even if introspection is disabled",
			},
		}
	}
	return nil
}

// checkAliasAbuse fires the same field many times under distinct aliases in one
// request. If the server processes all of them (200 + one data key per alias),
// per-field rate limiting / cost analysis is absent — the classic vector for
// GraphQL brute-force and DoS.
func (c *Client) checkAliasAbuse(ctx context.Context) *Finding {
	const n = 25
	var b strings.Builder
	b.WriteString(`{"query":"query { `)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, `a%d: __typename `, i)
	}
	b.WriteString(`}"}`)
	body, status, err := c.post(ctx, b.String())
	if err != nil || status != 200 {
		return nil
	}
	var raw struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if json.Unmarshal(body, &raw) != nil {
		return nil
	}
	if len(raw.Data) >= n {
		return &Finding{
			Class: "graphql-alias-abuse", Severity: "high",
			Detail: fmt.Sprintf("server resolved %d aliased fields in a single request", len(raw.Data)),
			Evidence: []string{
				fmt.Sprintf("sent %d aliases of __typename; server returned %d resolved keys", n, len(raw.Data)),
				"verified: no per-field cost/rate limiting — enables alias-based brute force and query amplification DoS",
			},
		}
	}
	return nil
}

// BatchProbe sends an array-batched query of the same operation repeated n times.
// A 200 with an n-element array response confirms batching is enabled (another
// rate-limit-bypass primitive).
func (c *Client) BatchProbe(ctx context.Context, n int) *Finding {
	var arr []string
	for i := 0; i < n; i++ {
		arr = append(arr, `{"query":"{ __typename }"}`)
	}
	body, status, err := c.post(ctx, "["+strings.Join(arr, ",")+"]")
	if err != nil || status != 200 {
		return nil
	}
	if bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
		var out []json.RawMessage
		if json.Unmarshal(body, &out) == nil && len(out) == n {
			return &Finding{
				Class: "graphql-batching", Severity: "medium",
				Detail: fmt.Sprintf("array batching enabled (%d operations executed in one request)", len(out)),
				Evidence: []string{"verified: server executed a JSON-array batch — rate limits keyed per-request are bypassable"},
			}
		}
	}
	return nil
}
