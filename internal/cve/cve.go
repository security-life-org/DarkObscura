// Package cve correlates a deterministically-detected technology version against
// a curated database of known CVEs. It only ever consumes a Confirmed
// fingerprint carrying an exact version, so its output is precise: a finding
// means "this confirmed version falls inside the published affected range of
// this CVE" — a deterministic fact, not a guess. It does not claim the instance
// is exploitable (that would need an active check), only that it runs an affected
// version, and the evidence says exactly that.
package cve

import (
	"strconv"
	"strings"

	"github.com/security-life-org/DarkObscura/internal/fingerprint"
)

// Vuln is a version-matched CVE.
type Vuln struct {
	Tech      string
	Version   string
	ID        string
	Severity  string
	Title     string
	Reference string
	Evidence  string
}

// rule is one CVE keyed to a technology and a version constraint.
type rule struct {
	tech       string
	constraint string // space-separated comparators, e.g. ">=2.4.0 <2.4.51"
	id         string
	severity   string
	title      string
	ref        string
}

// rules is a small, deliberately-accurate database of high-signal CVEs for the
// technologies fingerprint identifies with a version. Extend as needed.
var rules = []rule{
	{"Apache", "==2.4.49", "CVE-2021-41773", "critical",
		"Apache HTTP Server path traversal & RCE", "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
	{"Apache", "==2.4.50", "CVE-2021-42013", "critical",
		"Apache HTTP Server path traversal & RCE (incomplete 41773 fix)", "https://nvd.nist.gov/vuln/detail/CVE-2021-42013"},
	{"nginx", ">=0.6.18 <1.20.1", "CVE-2021-23017", "high",
		"nginx DNS resolver off-by-one heap write", "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"},
	{"Drupal", ">=7.0 <7.58", "CVE-2018-7600", "critical",
		"Drupalgeddon2 — unauthenticated remote code execution", "https://nvd.nist.gov/vuln/detail/CVE-2018-7600"},
	{"Drupal", ">=8.0 <8.5.1", "CVE-2018-7600", "critical",
		"Drupalgeddon2 — unauthenticated remote code execution", "https://nvd.nist.gov/vuln/detail/CVE-2018-7600"},
	{"Drupal", ">=7.0 <7.59", "CVE-2018-7602", "critical",
		"Drupalgeddon3 — authenticated remote code execution", "https://nvd.nist.gov/vuln/detail/CVE-2018-7602"},
	{"WordPress", ">=0 <5.8.3", "CVE-2022-21661", "high",
		"WordPress WP_Query SQL injection", "https://nvd.nist.gov/vuln/detail/CVE-2022-21661"},
	{"Microsoft IIS", "==7.5", "CVE-2015-1635", "critical",
		"HTTP.sys remote code execution (MS15-034)", "https://nvd.nist.gov/vuln/detail/CVE-2015-1635"},
}

// Correlate returns CVEs matching any Confirmed technology that carries a version.
func Correlate(techs []fingerprint.Tech) []Vuln {
	var out []Vuln
	for _, t := range techs {
		if t.Confidence != fingerprint.Confirmed || t.Version == "" {
			continue // only deterministic, versioned detections — keeps this zero-FP
		}
		for _, r := range rules {
			if !strings.EqualFold(r.tech, t.Name) {
				continue
			}
			if satisfies(t.Version, r.constraint) {
				out = append(out, Vuln{
					Tech: t.Name, Version: t.Version, ID: r.id, Severity: r.severity,
					Title: r.title, Reference: r.ref,
					Evidence: "confirmed: " + t.Name + " " + t.Version + " is within the affected range (" + r.constraint + ") of " + r.id,
				})
			}
		}
	}
	return out
}

// satisfies reports whether version meets every space-separated comparator in
// constraint (e.g. ">=2.4.0 <2.4.51", "==2.4.49").
func satisfies(version, constraint string) bool {
	for _, tok := range strings.Fields(constraint) {
		op, bound := splitComparator(tok)
		c := compareVersions(version, bound)
		ok := false
		switch op {
		case "==":
			ok = c == 0
		case "!=":
			ok = c != 0
		case "<":
			ok = c < 0
		case "<=":
			ok = c <= 0
		case ">":
			ok = c > 0
		case ">=":
			ok = c >= 0
		}
		if !ok {
			return false
		}
	}
	return true
}

func splitComparator(tok string) (op, bound string) {
	for _, o := range []string{">=", "<=", "==", "!=", ">", "<"} {
		if strings.HasPrefix(tok, o) {
			return o, strings.TrimPrefix(tok, o)
		}
	}
	return "==", tok
}

// compareVersions returns -1/0/1 comparing dotted numeric versions. Non-numeric
// segments are compared lexically as a fallback.
func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av, bv := "0", "0"
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		ai, aerr := strconv.Atoi(av)
		bi, berr := strconv.Atoi(bv)
		if aerr == nil && berr == nil {
			if ai != bi {
				if ai < bi {
					return -1
				}
				return 1
			}
			continue
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}
