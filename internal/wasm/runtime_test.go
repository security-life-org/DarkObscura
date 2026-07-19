package wasm

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// buildPlugin compiles the jwt-inspect sample plugin to wasm in a temp dir.
func buildPlugin(t *testing.T) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "jwt-inspect.wasm")
	cmd := exec.Command("go", "build", "-o", out, "../../plugins/jwt-inspect")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build plugin: %v\n%s", err, b)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRuntime_JWTPlugin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping wasm build/run in -short mode")
	}
	module := buildPlugin(t)

	ctx := context.Background()
	rt, err := NewRuntime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(ctx)

	// A response containing a JWT with alg=none — the plugin must flag it.
	// header {"alg":"none","typ":"JWT"} . payload {"sub":"1"} . (empty sig)
	jwt := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0."
	flow := map[string]any{
		"resp_body": []byte(`{"token":"` + jwt + `"}`),
	}
	blob, _ := json.Marshal(flow)

	findings, logs, err := rt.Run(ctx, "jwt-inspect", module, blob)
	if err != nil {
		t.Fatalf("run: %v (logs=%v)", err, logs)
	}
	var found bool
	for _, f := range findings {
		if f.Class == "jwt-alg-none" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected jwt-alg-none finding, got %+v (logs=%v)", findings, logs)
	}
}
