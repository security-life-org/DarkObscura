package sourcemap

import "testing"

func TestParse_ReconstructAndScan(t *testing.T) {
	m := `{"version":3,"sources":["src/api.js"],"sourcesContent":["const AWS='AKIA1234567890ABCD12'; fetch('/api/admin/users?id=1');"]}`
	res, err := Parse([]byte(m))
	if err != nil { t.Fatal(err) }
	if len(res.Sources) != 1 { t.Fatalf("expected 1 reconstructed source; got %d", len(res.Sources)) }
	if len(res.Secrets) == 0 { t.Error("expected the AWS key to be detected in reconstructed source") }
	found := false
	for _, e := range res.Endpoints { if e == "/api/admin/users?id=1" { found = true } }
	if !found { t.Errorf("expected endpoint mined from source; got %v", res.Endpoints) }
}
