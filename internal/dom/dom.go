// Package dom analyzes the client-side attack surface: DOM-based XSS source→sink
// flows, dangerous sinks, and tainted sources in a page's HTML and inline
// JavaScript. Static analysis alone cannot prove that a source actually reaches a
// sink at runtime, so every DOM-XSS result is reported at "possible" confidence
// and NEVER as confirmed — preserving the platform's rule that "confirmed" is
// reserved for deterministic proof. An optional headless renderer (build tag
// `chromedp`) executes the page in a real browser to observe the live DOM and
// runtime-loaded endpoints; without it, dom falls back to static analysis.
package dom

import (
	"regexp"
	"sort"
	"strings"
)

// Confidence grades a DOM finding. Static analysis maxes out at Possible.
type Confidence string

const (
	Possible Confidence = "possible"
	Likely   Confidence = "likely"
)

// Finding is a client-side observation.
type Finding struct {
	Class      string
	Confidence Confidence
	Sink       string
	Source     string
	Snippet    string
	Evidence   string
}

// sink regexes: DOM APIs that execute or inject markup/code.
var sinks = []struct {
	name string
	re   *regexp.Regexp
}{
	{"innerHTML", regexp.MustCompile(`\.innerHTML\s*\+?=`)},
	{"outerHTML", regexp.MustCompile(`\.outerHTML\s*\+?=`)},
	{"insertAdjacentHTML", regexp.MustCompile(`\.insertAdjacentHTML\s*\(`)},
	{"document.write", regexp.MustCompile(`document\.write(?:ln)?\s*\(`)},
	{"eval", regexp.MustCompile(`\beval\s*\(`)},
	{"Function", regexp.MustCompile(`\bnew\s+Function\s*\(`)},
	{"setTimeout(string)", regexp.MustCompile(`\bset(?:Timeout|Interval)\s*\(\s*['"` + "`" + `]`)},
	{"jQuery.html", regexp.MustCompile(`\$\([^)]*\)\.html\s*\(`)},
	{"location.assign", regexp.MustCompile(`location\s*(?:\.href)?\s*=|location\.(?:assign|replace)\s*\(`)},
	{"script.src", regexp.MustCompile(`\.src\s*=\s*[^;]*(?:location|document|params|hash|search)`)},
}

// source regexes: attacker-controllable inputs.
var sources = []struct {
	name string
	re   *regexp.Regexp
}{
	{"location.hash", regexp.MustCompile(`location\.hash`)},
	{"location.search", regexp.MustCompile(`location\.search`)},
	{"location.href", regexp.MustCompile(`location\.href`)},
	{"document.URL", regexp.MustCompile(`document\.(?:URL|documentURI|baseURI)`)},
	{"document.referrer", regexp.MustCompile(`document\.referrer`)},
	{"window.name", regexp.MustCompile(`window\.name`)},
	{"postMessage", regexp.MustCompile(`addEventListener\s*\(\s*['"` + "`" + `]message`)},
	{"URLSearchParams", regexp.MustCompile(`new\s+URLSearchParams`)},
}

// inline event-handler attributes in HTML (onerror=, onclick=, …).
var eventHandlerRe = regexp.MustCompile(`(?i)\son[a-z]+\s*=\s*["'][^"']+["']`)

// Analyze runs static DOM analysis over a page body (HTML + inline JS). It
// reports possible DOM-XSS flows when both a tainted source and a dangerous sink
// are present, plus an inventory of sinks/sources for the operator.
func Analyze(body []byte) []Finding {
	text := string(body)
	foundSinks := detect(text, func() []named { return sinkList() })
	foundSources := detect(text, func() []named { return sourceList() })

	var out []Finding
	// Possible DOM-XSS: co-occurrence of a source and a sink in the same document.
	if len(foundSinks) > 0 && len(foundSources) > 0 {
		for _, sk := range foundSinks {
			for _, sr := range foundSources {
				out = append(out, Finding{
					Class: "dom-xss", Confidence: Possible,
					Sink: sk.name, Source: sr.name,
					Snippet:  sk.snippet,
					Evidence: "possible DOM-XSS: tainted source " + sr.name + " and dangerous sink " + sk.name + " co-occur — manual/dynamic confirmation required",
				})
			}
		}
	}
	// Standalone sink inventory (informational).
	for _, sk := range foundSinks {
		out = append(out, Finding{
			Class: "dom-sink", Confidence: Possible, Sink: sk.name, Snippet: sk.snippet,
			Evidence: "dangerous DOM sink present: " + sk.name,
		})
	}
	// Inline event handlers (potential injection contexts).
	for _, m := range dedupStrings(eventHandlerRe.FindAllString(text, -1)) {
		out = append(out, Finding{
			Class: "inline-event-handler", Confidence: Possible,
			Snippet: strings.TrimSpace(m), Evidence: "inline event handler present (CSP-unfriendly, potential injection sink)",
		})
	}
	return out
}

type named struct {
	name    string
	re      *regexp.Regexp
	snippet string
}

func sinkList() []named {
	var l []named
	for _, s := range sinks {
		l = append(l, named{name: s.name, re: s.re})
	}
	return l
}
func sourceList() []named {
	var l []named
	for _, s := range sources {
		l = append(l, named{name: s.name, re: s.re})
	}
	return l
}

func detect(text string, list func() []named) []named {
	var out []named
	for _, n := range list() {
		if loc := n.re.FindStringIndex(text); loc != nil {
			n.snippet = snippet(text, loc[0])
			out = append(out, n)
		}
	}
	return out
}

func snippet(text string, at int) string {
	from := at - 20
	if from < 0 {
		from = 0
	}
	to := at + 60
	if to > len(text) {
		to = len(text)
	}
	return strings.TrimSpace(strings.ReplaceAll(text[from:to], "\n", " "))
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
