// Package report turns confirmed findings into professional deliverables. JSON
// alone keeps DarkObscura out of two workflows that matter: CI/CD security gates
// (which consume SARIF) and client/bug-bounty submissions (which want a readable
// document). report renders SARIF 2.1.0 for the former and a standalone,
// print-to-PDF HTML report for the latter, straight from a slice of
// exploit.Finding.
package report

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/security-life-org/DarkObscura/internal/exploit"
)

// SARIF renders findings as a SARIF 2.1.0 log (the format GitHub/GitLab security
// dashboards ingest).
func SARIF(findings []exploit.Finding, toolVersion string) ([]byte, error) {
	type message struct {
		Text string `json:"text"`
	}
	type artifactLocation struct {
		URI string `json:"uri"`
	}
	type physicalLocation struct {
		ArtifactLocation artifactLocation `json:"artifactLocation"`
	}
	type location struct {
		PhysicalLocation physicalLocation `json:"physicalLocation"`
	}
	type result struct {
		RuleID    string     `json:"ruleId"`
		Level     string     `json:"level"`
		Message   message    `json:"message"`
		Locations []location `json:"locations"`
	}
	type rule struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	type driver struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Rules   []rule `json:"rules"`
	}
	type tool struct {
		Driver driver `json:"driver"`
	}
	type run struct {
		Tool    tool     `json:"tool"`
		Results []result `json:"results"`
	}
	type sarif struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []run  `json:"runs"`
	}

	ruleSet := map[string]bool{}
	var rules []rule
	var results []result
	for _, f := range findings {
		if !ruleSet[f.Class] {
			ruleSet[f.Class] = true
			rules = append(rules, rule{ID: f.Class, Name: f.Class})
		}
		results = append(results, result{
			RuleID:  f.Class,
			Level:   sarifLevel(f.Severity),
			Message: message{Text: strings.Join(append([]string{f.Class + " via " + f.VerifiedVia}, f.Evidence...), " | ")},
			Locations: []location{{PhysicalLocation: physicalLocation{
				ArtifactLocation: artifactLocation{URI: f.Target}}}},
		})
	}
	doc := sarif{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []run{{
			Tool:    tool{Driver: driver{Name: "DarkObscura", Version: toolVersion, Rules: rules}},
			Results: results,
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func sarifLevel(s exploit.Severity) string {
	switch s {
	case exploit.SevCritical, exploit.SevHigh:
		return "error"
	case exploit.SevMedium:
		return "warning"
	default:
		return "note"
	}
}

// HTML renders a standalone, self-contained report suitable for print-to-PDF.
func HTML(findings []exploit.Finding, title, toolVersion string, generated time.Time) string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=utf-8><title>")
	b.WriteString(html.EscapeString(title))
	b.WriteString(`</title><style>
body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;color:#0d1117;max-width:900px;margin:2rem auto;padding:0 1rem}
h1{border-bottom:2px solid #6f42c1;padding-bottom:.3rem}
.f{border:1px solid #d0d7de;border-left-width:6px;border-radius:6px;padding:1rem;margin:1rem 0}
.critical{border-left-color:#a40e26}.high{border-left-color:#d1242f}.medium{border-left-color:#bf8700}.low{border-left-color:#0969da}.info{border-left-color:#6e7781}
.sev{font-weight:700;text-transform:uppercase;font-size:12px}
code{background:#f6f8fa;padding:.1rem .3rem;border-radius:4px}
ul{margin:.4rem 0}
.meta{color:#6e7781;font-size:12px}
@media print{.f{break-inside:avoid}}
</style></head><body>`)
	fmt.Fprintf(&b, "<h1>%s</h1>", html.EscapeString(title))
	fmt.Fprintf(&b, `<p class=meta>DarkObscura %s · generated %s · %d confirmed finding(s)</p>`,
		html.EscapeString(toolVersion), generated.Format(time.RFC1123), len(findings))

	counts := map[exploit.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	fmt.Fprintf(&b, `<p class=meta>critical:%d high:%d medium:%d low:%d</p>`,
		counts[exploit.SevCritical], counts[exploit.SevHigh], counts[exploit.SevMedium], counts[exploit.SevLow])

	for i, f := range findings {
		fmt.Fprintf(&b, `<div class="f %s">`, string(f.Severity))
		fmt.Fprintf(&b, `<div class=sev>#%d %s · %s</div>`, i+1, html.EscapeString(f.Class), string(f.Severity))
		fmt.Fprintf(&b, `<p><b>Target:</b> <code>%s</code><br><b>Parameter:</b> <code>%s</code><br><b>Verified via:</b> %s</p>`,
			html.EscapeString(f.Target), html.EscapeString(f.Param), html.EscapeString(f.VerifiedVia))
		if f.Payload != "" {
			fmt.Fprintf(&b, `<p><b>Payload:</b> <code>%s</code></p>`, html.EscapeString(f.Payload))
		}
		if len(f.Evidence) > 0 {
			b.WriteString("<b>Evidence:</b><ul>")
			for _, e := range f.Evidence {
				fmt.Fprintf(&b, "<li>%s</li>", html.EscapeString(e))
			}
			b.WriteString("</ul>")
		}
		b.WriteString("</div>")
	}
	if len(findings) == 0 {
		b.WriteString("<p>No confirmed vulnerabilities (zero false positives by design).</p>")
	}
	b.WriteString("</body></html>")
	return b.String()
}
