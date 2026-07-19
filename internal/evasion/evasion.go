// Package evasion provides WAF fingerprinting and payload mutation. A precise
// scanner is worthless if the payload never reaches the application: a WAF in
// front of the target blocks the canonical payload and the scanner records a
// false negative ("looks safe"). evasion fingerprints the WAF from its block
// response and generates encoding/obfuscation variants of a payload that are
// semantically equivalent but syntactically different, so the verification
// oracle still recognizes a real hit. Mutations are ordered least-to-most exotic
// so the cheapest bypass is tried first.
package evasion

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// WAF is a fingerprinted web application firewall.
type WAF struct {
	Name       string
	Confidence string // "high" | "medium"
	Signal     string // what matched
}

// signature maps a vendor to header/body indicators.
type signature struct {
	name    string
	headers map[string]*regexp.Regexp // header name -> value pattern (nil = presence)
	body    *regexp.Regexp
	server  *regexp.Regexp
}

var signatures = []signature{
	{name: "Cloudflare", headers: map[string]*regexp.Regexp{"Server": regexp.MustCompile(`(?i)cloudflare`), "CF-RAY": nil}, body: regexp.MustCompile(`(?i)attention required|cloudflare`)},
	{name: "AWS WAF / CloudFront", headers: map[string]*regexp.Regexp{"X-Amzn-RequestId": nil, "X-Amz-Cf-Id": nil}, server: regexp.MustCompile(`(?i)cloudfront|awselb`)},
	{name: "Akamai", headers: map[string]*regexp.Regexp{"X-Akamai-Transformed": nil}, server: regexp.MustCompile(`(?i)akamai`)},
	{name: "Imperva Incapsula", headers: map[string]*regexp.Regexp{"X-Iinfo": nil, "X-CDN": regexp.MustCompile(`(?i)incapsula`)}, body: regexp.MustCompile(`(?i)incapsula|_Incapsula_Resource`)},
	{name: "F5 BIG-IP ASM", headers: map[string]*regexp.Regexp{"Set-Cookie": regexp.MustCompile(`(?i)TS[0-9a-f]{6,}|BIGipServer`)}, body: regexp.MustCompile(`(?i)the requested url was rejected`)},
	{name: "ModSecurity", server: regexp.MustCompile(`(?i)mod_security|modsecurity`), body: regexp.MustCompile(`(?i)mod_security|not acceptable`)},
	{name: "Sucuri", headers: map[string]*regexp.Regexp{"X-Sucuri-ID": nil, "Server": regexp.MustCompile(`(?i)sucuri`)}},
}

// Fingerprint inspects a response (ideally the WAF's block/challenge page) and
// returns the detected WAF, or nil if none matched.
func Fingerprint(header http.Header, body []byte) *WAF {
	server := header.Get("Server")
	for _, sig := range signatures {
		for hn, pat := range sig.headers {
			v := header.Get(hn)
			if v == "" {
				continue
			}
			if pat == nil || pat.MatchString(v) {
				return &WAF{Name: sig.name, Confidence: "high", Signal: "header " + hn}
			}
		}
		if sig.server != nil && sig.server.MatchString(server) {
			return &WAF{Name: sig.name, Confidence: "high", Signal: "Server header"}
		}
		if sig.body != nil && sig.body.Match(body) {
			return &WAF{Name: sig.name, Confidence: "medium", Signal: "block-page body"}
		}
	}
	return nil
}

// Mutation is one obfuscated variant of a payload plus a label describing the
// technique that produced it.
type Mutation struct {
	Technique string
	Payload   string
}

// Mutate returns semantically-equivalent obfuscations of payload, ordered from
// cheapest/most-compatible to most exotic. The original is always first so the
// caller can fall back to it.
func Mutate(payload string) []Mutation {
	out := []Mutation{{Technique: "identity", Payload: payload}}
	out = append(out,
		Mutation{"url-encode", urlEncodeAll(payload)},
		Mutation{"double-url-encode", urlEncodeAll(urlEncodeAll(payload))},
		Mutation{"mixed-case", mixedCase(payload)},
		Mutation{"sql-comment-inject", sqlCommentInject(payload)},
		Mutation{"unicode-escape", unicodeEscape(payload)},
		Mutation{"html-entity", htmlEntity(payload)},
		Mutation{"whitespace-swap", whitespaceSwap(payload)},
		// round-2: doubled technique set.
		Mutation{"html-hex-entity", htmlHexEntity(payload)},
		Mutation{"overlong-utf8", overlongUTF8(payload)},
		Mutation{"null-byte-inject", nullByteInject(payload)},
		Mutation{"newline-swap", strings.ReplaceAll(payload, " ", "\n")},
		Mutation{"plus-for-space", strings.ReplaceAll(payload, " ", "+")},
		Mutation{"double-encode-slash", strings.ReplaceAll(urlEncodeAll(payload), "%2F", "%252F")},
		Mutation{"sql-scientific-space", strings.ReplaceAll(payload, " ", "/*!50000 */")},
		Mutation{"case-plus-comment", sqlCommentInject(mixedCase(payload))},
		Mutation{"unicode-fullwidth", fullwidth(payload)},
	)
	return out
}

func urlEncodeAll(s string) string {
	var b strings.Builder
	for _, r := range []byte(s) {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteByte(r)
		} else {
			fmt.Fprintf(&b, "%%%02X", r)
		}
	}
	return b.String()
}

func mixedCase(s string) string {
	var b strings.Builder
	upper := false
	for _, r := range s {
		if r >= 'a' && r <= 'z' && upper {
			b.WriteRune(r - 32)
		} else if r >= 'A' && r <= 'Z' && !upper {
			b.WriteRune(r + 32)
		} else {
			b.WriteRune(r)
		}
		upper = !upper
	}
	return b.String()
}

// sqlCommentInject splices inline comments between SQL keywords to break naive
// signature matching (e.g. "UNION SELECT" -> "UNION/**/SELECT").
func sqlCommentInject(s string) string {
	r := strings.NewReplacer(
		" ", "/**/",
		"UNION", "UN/**/ION",
		"SELECT", "SEL/**/ECT",
		"OR", "O/**/R",
		"AND", "A/**/ND",
	)
	return r.Replace(s)
}

func unicodeEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			b.WriteRune(r)
			continue
		}
		fmt.Fprintf(&b, "\\u%04x", r)
	}
	return b.String()
}

func htmlEntity(s string) string {
	var b strings.Builder
	for _, r := range s {
		fmt.Fprintf(&b, "&#%d;", r)
	}
	return b.String()
}

func whitespaceSwap(s string) string {
	// Replace spaces with alternative whitespace/comment tokens WAFs often miss.
	return strings.ReplaceAll(s, " ", "\t")
}

// htmlHexEntity encodes each byte as a hex HTML entity (&#x..;).
func htmlHexEntity(s string) string {
	var b strings.Builder
	for _, r := range s {
		fmt.Fprintf(&b, "&#x%x;", r)
	}
	return b.String()
}

// overlongUTF8 emits an overlong 2-byte UTF-8 encoding of ASCII bytes, a classic
// normalization-bypass trick against filters that decode after inspection.
func overlongUTF8(s string) string {
	var b strings.Builder
	for _, r := range []byte(s) {
		if r < 0x80 {
			fmt.Fprintf(&b, "%%C0%%%02X", 0x80|r)
		} else {
			fmt.Fprintf(&b, "%%%02X", r)
		}
	}
	return b.String()
}

// nullByteInject appends a URL-encoded null byte, historically effective at
// truncating server-side string handling.
func nullByteInject(s string) string { return s + "%00" }

// fullwidth maps ASCII to its Unicode fullwidth form (U+FF01..U+FF5E), which some
// backends normalize back to ASCII after the WAF has already passed the request.
func fullwidth(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x21 && r <= 0x7e {
			b.WriteRune(r + 0xFEE0)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
