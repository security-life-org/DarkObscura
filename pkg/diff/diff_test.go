package diff

import "testing"

func TestCompare_Identical(t *testing.T) {
	body := []byte(`{"ok":true,"items":[1,2,3]}`)
	r := Compare(body, 200, body, 200)
	if r.Significant() {
		t.Fatalf("identical responses must not be significant: %+v", r)
	}
	if r.ByteSimilarity < 0.99 {
		t.Errorf("ByteSimilarity = %.2f, want ~1", r.ByteSimilarity)
	}
}

func TestCompare_StructuralChange(t *testing.T) {
	base := []byte(`{"user":{"id":1,"name":"a"}}`)
	cand := []byte(`{"user":{"id":1,"name":"a","is_admin":true}}`)
	r := Compare(base, 200, cand, 200)
	if !r.StructuralChange {
		t.Fatalf("expected structural change, got %+v", r)
	}
	if !r.Significant() {
		t.Errorf("structural change must be significant")
	}
	found := false
	for _, k := range r.AddedKeys {
		if k == "user.is_admin" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected added key user.is_admin, got %v", r.AddedKeys)
	}
}

func TestCompare_StatusChange(t *testing.T) {
	r := Compare([]byte("ok"), 200, []byte("error"), 500)
	if !r.StatusChanged || !r.Significant() {
		t.Fatalf("status change must be significant: %+v", r)
	}
}

func TestCompare_ReflectionNoise(t *testing.T) {
	// A single reflected quote character should NOT by itself be significant
	// (guards against reflection-only false positives).
	base := []byte(`<p>results for: foo</p>`)
	cand := []byte(`<p>results for: foo'</p>`)
	r := Compare(base, 200, cand, 200)
	if r.Significant() {
		t.Fatalf("tiny reflected change must not be significant: %+v", r)
	}
}
