package importer

import (
	"strings"
	"testing"
)

func TestParseOpenAPI3(t *testing.T) {
	spec := []byte(`{
		"openapi": "3.0.0",
		"servers": [{"url": "https://api.example.com/v1"}],
		"paths": {
			"/users/{id}": {"get": {"parameters": [
				{"name": "id", "in": "path"},
				{"name": "verbose", "in": "query"}
			]}},
			"/search": {"get": {"parameters": [{"name": "q", "in": "query"}]}}
		}
	}`)
	eps, err := ParseOpenAPI(spec, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints, got %d: %+v", len(eps), eps)
	}
	var foundUser bool
	for _, e := range eps {
		if strings.Contains(e.URL, "/users/1") && strings.Contains(e.URL, "verbose=1") {
			foundUser = true
			if e.Method != "GET" {
				t.Errorf("method = %s", e.Method)
			}
		}
	}
	if !foundUser {
		t.Errorf("expected /users/1?verbose=1 endpoint; got %+v", eps)
	}
}

func TestParseSwagger2WithOverride(t *testing.T) {
	spec := []byte(`{
		"swagger": "2.0",
		"host": "petstore.example.com",
		"basePath": "/api",
		"schemes": ["https"],
		"paths": {"/pet/{petId}": {"get": {"parameters": [{"name": "petId", "in": "path"}]}}}
	}`)
	eps, err := ParseOpenAPI(spec, "http://127.0.0.1:8099")
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(eps))
	}
	if !strings.HasPrefix(eps[0].URL, "http://127.0.0.1:8099/pet/1") {
		t.Errorf("override base not applied: %s", eps[0].URL)
	}
}
