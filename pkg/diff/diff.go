// Package diff implements the differential-analysis primitives behind
// DarkObscura's zero-false-positive verification: it compares a payload response
// against a captured baseline at both the byte level and the structural
// (AST/shape) level, so a finding fires on real structural change rather than an
// incidental string match.
package diff

import (
	"encoding/json"
	"math"
	"reflect"
)

// Report summarizes how a candidate response differs from a baseline.
type Report struct {
	ByteSimilarity   float64 // 0..1 normalized byte-level similarity
	LengthDelta      int     // len(candidate) - len(baseline)
	StatusChanged    bool
	StructuralChange bool    // JSON shape / key-set changed
	AddedKeys        []string
	RemovedKeys      []string
	Notes            []string
}

// Significant reports whether the difference is strong enough to treat as a real
// behavioral change (used as one gate in the verification pipeline).
func (r Report) Significant() bool {
	return r.StatusChanged || r.StructuralChange || r.ByteSimilarity < 0.90 ||
		abs(r.LengthDelta) > 64
}

// Compare produces a Report comparing candidate against baseline. baseStatus and
// candStatus are the HTTP status codes.
func Compare(baseline []byte, baseStatus int, candidate []byte, candStatus int) Report {
	r := Report{
		LengthDelta:    len(candidate) - len(baseline),
		StatusChanged:  baseStatus != candStatus,
		ByteSimilarity: byteSimilarity(baseline, candidate),
	}
	if r.StatusChanged {
		r.Notes = append(r.Notes, "HTTP status changed")
	}

	// Structural (JSON) comparison when both parse as JSON.
	var bj, cj any
	if json.Unmarshal(baseline, &bj) == nil && json.Unmarshal(candidate, &cj) == nil {
		added, removed := keyDiff(bj, cj, "")
		r.AddedKeys, r.RemovedKeys = added, removed
		if len(added) > 0 || len(removed) > 0 || !sameShape(bj, cj) {
			r.StructuralChange = true
			r.Notes = append(r.Notes, "JSON structure changed")
		}
	}
	return r
}

// byteSimilarity returns a cheap normalized similarity based on length ratio and
// a shared-prefix/suffix heuristic. 1.0 == identical.
func byteSimilarity(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	maxLen := math.Max(float64(len(a)), float64(len(b)))
	if maxLen == 0 {
		return 1
	}
	// Shared prefix.
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	// Shared suffix (not overlapping the prefix).
	j := 0
	for j < len(a)-i && j < len(b)-i && a[len(a)-1-j] == b[len(b)-1-j] {
		j++
	}
	shared := float64(i + j)
	return shared / maxLen
}

// keyDiff returns keys present only in b (added) and only in a (removed),
// recursing into nested JSON objects with dotted paths.
func keyDiff(a, b any, prefix string) (added, removed []string) {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if !aok || !bok {
		return nil, nil
	}
	for k := range bm {
		key := join(prefix, k)
		if _, ok := am[k]; !ok {
			added = append(added, key)
		} else {
			na, nr := keyDiff(am[k], bm[k], key)
			added = append(added, na...)
			removed = append(removed, nr...)
		}
	}
	for k := range am {
		if _, ok := bm[k]; !ok {
			removed = append(removed, join(prefix, k))
		}
	}
	return added, removed
}

// sameShape reports whether two JSON values have the same recursive type shape,
// ignoring scalar values.
func sameShape(a, b any) bool {
	if reflect.TypeOf(a) != reflect.TypeOf(b) {
		return false
	}
	switch at := a.(type) {
	case map[string]any:
		bt := b.(map[string]any)
		if len(at) != len(bt) {
			return false
		}
		for k, av := range at {
			bv, ok := bt[k]
			if !ok || !sameShape(av, bv) {
				return false
			}
		}
	case []any:
		bt := b.([]any)
		if len(at) != len(bt) {
			return false
		}
		for i := range at {
			if !sameShape(at[i], bt[i]) {
				return false
			}
		}
	}
	return true
}

func join(prefix, k string) string {
	if prefix == "" {
		return k
	}
	return prefix + "." + k
}

func abs(i int) int {
	if i < 0 {
		return -i
	}
	return i
}
