// Package parser provides pooled, allocation-conscious parsers for the content
// types DarkObscura inspects (HTML, JSON, XML, GraphQL) and a parameter
// extractor that classifies each discovered parameter by risk profile.
package parser

import (
	"regexp"
	"strings"
)

// RiskProfile ranks how interesting a parameter is as an attack surface.
type RiskProfile int

const (
	RiskLow RiskProfile = iota
	RiskMedium
	RiskHigh
	RiskCritical
)

func (r RiskProfile) String() string {
	switch r {
	case RiskCritical:
		return "critical"
	case RiskHigh:
		return "high"
	case RiskMedium:
		return "medium"
	default:
		return "low"
	}
}

// Param is a discovered input parameter.
type Param struct {
	Name     string      // parameter name
	Value    string      // observed value (may be empty)
	Location string      // query | body | json | header | graphql | form
	Risk     RiskProfile // classified risk
	Reasons  []string    // why it got this risk (for reporting)
}

// Classifier assigns a RiskProfile to a parameter name/value pair. Rules are
// evaluated most-specific first; the highest matching risk wins.
type Classifier struct {
	rules []classRule
}

type classRule struct {
	re     *regexp.Regexp
	risk   RiskProfile
	reason string
}

// DefaultClassifier returns a classifier seeded with common high-signal names.
func DefaultClassifier() *Classifier {
	mk := func(pat string) *regexp.Regexp { return regexp.MustCompile(`(?i)` + pat) }
	return &Classifier{rules: []classRule{
		{mk(`(^|_)(id|uid|uuid|gid)$|_id$`), RiskHigh, "identifier — IDOR/SQLi candidate"},
		{mk(`user|account|customer|member|owner`), RiskHigh, "identity reference — IDOR candidate"},
		{mk(`file|path|dir|folder|template|include|page`), RiskHigh, "path reference — LFI/path-traversal candidate"},
		{mk(`url|uri|redirect|next|dest|callback|webhook|target`), RiskHigh, "URL reference — SSRF/open-redirect candidate"},
		{mk(`cmd|exec|command|run|shell|ping|query|q|search|filter`), RiskCritical, "command/query surface — RCE/injection candidate"},
		{mk(`sort|order|orderby|group|column|field|table|select`), RiskHigh, "SQL structure hint — SQLi candidate"},
		{mk(`token|auth|session|key|secret|password|passwd|pwd|role|admin|priv`), RiskCritical, "auth/privilege material — authz-bypass candidate"},
		{mk(`amount|price|qty|quantity|balance|discount|coupon`), RiskMedium, "value/business-logic surface"},
		{mk(`email|phone|name|address`), RiskMedium, "PII surface"},
		{mk(`color|theme|lang|locale|tab|view|mode|style`), RiskLow, "presentation-only surface"},
	}}
}

// Classify returns the risk profile for a parameter.
func (c *Classifier) Classify(name, value string) (RiskProfile, []string) {
	best := RiskLow
	var reasons []string
	for _, r := range c.rules {
		if r.re.MatchString(name) {
			if r.risk > best {
				best = r.risk
			}
			reasons = append(reasons, r.reason)
		}
	}
	// Value-based bumps: values that look like paths/URLs raise low-risk names.
	if best < RiskMedium {
		if strings.Contains(value, "://") || strings.HasPrefix(value, "/") {
			best = RiskMedium
			reasons = append(reasons, "value resembles a URL/path")
		}
	}
	if reasons == nil {
		reasons = []string{"no high-signal pattern matched"}
	}
	return best, reasons
}

// ClassifyParams annotates a slice of params in place and returns it.
func (c *Classifier) ClassifyParams(ps []Param) []Param {
	for i := range ps {
		ps[i].Risk, ps[i].Reasons = c.Classify(ps[i].Name, ps[i].Value)
	}
	return ps
}
