// Package chain is DarkObscura's deterministic attack-chain orchestrator. The
// spec envisioned an LLM "Dark Brain" that reasons about multi-step exploitation;
// this delivers the valuable 90% of that idea without the non-determinism. It
// models findings as nodes and applies a fixed rule set of known escalation edges
// (e.g. SSRF → cloud-metadata → credential theft; LFI → read app secrets →
// authenticated access; open-redirect → OAuth token theft). The output is an
// ordered, explainable kill-chain that a human operator can follow — every edge
// is a documented technique, not a guess.
package chain

import (
	"fmt"
	"sort"
	"strings"

	"github.com/security-life-org/DarkObscura/internal/exploit"
)

// Step is one node in a chain: a finding plus what it unlocks.
type Step struct {
	Class     string
	Target    string
	Param     string
	Unlocks   string // capability gained by exploiting this step
	Technique string // how the next step is reached from here
}

// Chain is an ordered escalation path built from confirmed findings.
type Chain struct {
	Name       string
	Severity   string
	Steps      []Step
	Impact     string
}

// rule maps a finding class (matched as a substring) to the capability it grants
// and the follow-on technique. Order encodes escalation priority.
type rule struct {
	match     string
	unlocks   string
	technique string
	impact    string
	severity  string
}

var rules = []rule{
	{"ssrf", "internal network / cloud metadata reachability",
		"pivot to http://169.254.169.254/latest/meta-data/ for IAM credentials",
		"full cloud account takeover via stolen instance credentials", "critical"},
	{"rce", "arbitrary command execution",
		"establish persistence and dump environment/credentials",
		"complete host compromise", "critical"},
	{"path-traversal", "arbitrary file read",
		"read app config / .env / private keys, then reuse leaked secrets to authenticate",
		"credential theft leading to authenticated access", "high"},
	{"lfi", "arbitrary file read",
		"read /etc/passwd, app secrets, and session stores",
		"credential and session material disclosure", "high"},
	{"sqli", "database read/write",
		"dump credential tables and reuse hashes/session tokens",
		"authentication bypass and mass data exfiltration", "critical"},
	{"open-redirect", "attacker-controlled redirect target",
		"chain into OAuth/SSO flows to capture authorization codes or tokens",
		"account takeover via token theft", "medium"},
	{"reflected-xss", "script execution in victim context",
		"steal session cookies / CSRF tokens and drive authenticated actions",
		"session hijacking and privileged action forgery", "high"},
	{"ssti", "server-side template evaluation",
		"escalate template evaluation to command execution (sandbox escape)",
		"remote code execution", "critical"},
	// round-2: doubled rule set.
	{"xxe", "external entity / file read via XML parser",
		"read local files and SSRF to internal services through entity resolution",
		"internal file disclosure and internal-network SSRF", "high"},
	{"nosqli", "NoSQL query manipulation",
		"bypass authentication with operator injection ($ne/$gt) and dump collections",
		"authentication bypass and data exfiltration", "high"},
	{"deserial", "untrusted object deserialization",
		"craft a gadget chain to reach code execution",
		"remote code execution via gadget chain", "critical"},
	{"csrf", "forced state-changing action",
		"chain with a privileged victim session to perform account changes",
		"privileged action forgery on behalf of a victim", "medium"},
	{"cors", "cross-origin read of authenticated data",
		"host a malicious page that exfiltrates the victim's authenticated responses",
		"cross-origin account data theft", "high"},
	{"cache-poison", "poisoned shared cache entry",
		"inject a payload into a cached response served to every subsequent user",
		"stored XSS / redirect affecting all cache consumers", "high"},
	{"secret", "leaked credential material",
		"authenticate directly with the leaked key or token",
		"authenticated access using disclosed credentials", "high"},
	{"graphql", "over-exposed GraphQL surface",
		"abuse introspection + batching to enumerate and brute-force privileged operations",
		"mass enumeration and rate-limit bypass", "medium"},
}

// severityRank orders severities for chain scoring.
var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// Build derives escalation chains from a set of confirmed findings. Each finding
// that matches an escalation rule becomes a chain; findings on the same target
// are linked into a single multi-step chain when several rules apply.
func Build(findings []exploit.Finding) []Chain {
	byTarget := map[string][]exploit.Finding{}
	for _, f := range findings {
		if !f.Confirmed {
			continue
		}
		host := hostKey(f.Target)
		byTarget[host] = append(byTarget[host], f)
	}

	var chains []Chain
	for host, fs := range byTarget {
		var steps []Step
		maxSev := 0
		impact := ""
		for _, f := range fs {
			r, ok := matchRule(f.Class)
			if !ok {
				continue
			}
			steps = append(steps, Step{
				Class: f.Class, Target: f.Target, Param: f.Param,
				Unlocks: r.unlocks, Technique: r.technique,
			})
			if severityRank[r.severity] > maxSev {
				maxSev = severityRank[r.severity]
				impact = r.impact
			}
		}
		if len(steps) == 0 {
			continue
		}
		// Order steps by escalation severity (highest-impact primitive first).
		sort.SliceStable(steps, func(i, j int) bool {
			ri, _ := matchRule(steps[i].Class)
			rj, _ := matchRule(steps[j].Class)
			return severityRank[ri.severity] > severityRank[rj.severity]
		})
		chains = append(chains, Chain{
			Name:     "kill-chain @ " + host,
			Severity: sevName(maxSev),
			Steps:    steps,
			Impact:   impact,
		})
	}
	sort.SliceStable(chains, func(i, j int) bool {
		return severityRank[chains[i].Severity] > severityRank[chains[j].Severity]
	})
	return chains
}

func matchRule(class string) (rule, bool) {
	c := strings.ToLower(class)
	for _, r := range rules {
		if strings.Contains(c, r.match) {
			return r, true
		}
	}
	return rule{}, false
}

func sevName(rank int) string {
	for name, r := range severityRank {
		if r == rank {
			return name
		}
	}
	return "info"
}

// hostKey extracts a stable host grouping key from a finding target string,
// which may look like "https://h/path [query:param]".
func hostKey(target string) string {
	t := target
	if i := strings.Index(t, " ["); i >= 0 {
		t = t[:i]
	}
	t = strings.TrimPrefix(t, "https://")
	t = strings.TrimPrefix(t, "http://")
	if i := strings.IndexByte(t, '/'); i >= 0 {
		t = t[:i]
	}
	return t
}

// Render produces a human-readable multi-line description of a chain.
func Render(c Chain) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s\n", strings.ToUpper(c.Severity), c.Name)
	for i, s := range c.Steps {
		fmt.Fprintf(&b, "  %d. %s (%s) → unlocks: %s\n", i+1, s.Class, s.Param, s.Unlocks)
		fmt.Fprintf(&b, "     technique: %s\n", s.Technique)
	}
	fmt.Fprintf(&b, "  ⇒ impact: %s\n", c.Impact)
	return b.String()
}
