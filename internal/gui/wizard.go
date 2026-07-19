package gui

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/security-life-org/DarkObscura/internal/engine"
	"github.com/security-life-org/DarkObscura/internal/exploit"
	"github.com/security-life-org/DarkObscura/internal/parser"
)

// RunWizard drives an interactive, guided scan from the terminal — the friendly
// path for users who don't want to remember flags. It reads from in and writes
// prompts to out.
func RunWizard(ctx context.Context, in io.Reader, out io.Writer) error {
	r := bufio.NewReader(in)
	p := func(format string, a ...any) { fmt.Fprintf(out, format, a...) }

	p("\n┌───────────────────────────────────────────────┐\n")
	p("│  DarkObscura — Guided Scan Wizard              │\n")
	p("└───────────────────────────────────────────────┘\n\n")

	// 1. Target.
	target := ask(r, out, "Target URL (include a query param, e.g. https://site/path?id=1):\n> ")
	if target == "" {
		return fmt.Errorf("wizard: no target provided")
	}

	// 2. Show what we discovered + how it's classified, before doing anything.
	ext := parser.NewExtractor(nil)
	params := ext.FromQuery(queryOf(target))
	if len(params) == 0 {
		p("\n⚠  No query parameters found in that URL. DarkObscura fuzzes parameters,\n")
		p("   so add at least one (e.g. ?id=1) and re-run.\n")
		return nil
	}
	p("\nDiscovered %d parameter(s):\n", len(params))
	for _, pr := range params {
		p("  • %-16s risk=%s\n", pr.Name, pr.Risk)
	}
	medium := 0
	for _, pr := range params {
		if pr.Risk >= parser.RiskMedium {
			medium++
		}
	}
	p("\n%d of these are medium+ risk and will be actively probed.\n", medium)

	// 3. Authorization gate — explicit, in plain language.
	p("\n\033[1mDarkObscura sends live attack payloads to the target.\033[0m\n")
	ans := strings.ToLower(ask(r, out, "Are you authorized to test this target? (yes/no)\n> "))
	if ans != "yes" && ans != "y" {
		p("\nAborted. Only scan systems you own or are explicitly permitted to test.\n")
		return nil
	}

	// 4. OOB canary (optional).
	useCanary := false
	if strings.HasPrefix(strings.ToLower(ask(r, out,
		"\nEnable out-of-band (SSRF/RCE) confirmation? Needs a delegated DNS zone. (yes/no)\n> ")), "y") {
		useCanary = true
	}
	var canary *exploit.CanaryServer
	if useCanary {
		zone := ask(r, out, "Canary DNS zone (e.g. canary.example.com):\n> ")
		if zone != "" {
			canary = exploit.NewCanaryServer(zone, nil)
			go canary.ListenAndServe(ctx, ":53", ":8081")
			p("  canary listening on :53 (dns) and :8081 (http)\n")
		}
	}

	// 5. Run.
	p("\nScanning %s …\n", target)
	sess, err := engine.NewSession()
	if err != nil {
		return err
	}
	fuzzer := exploit.NewFuzzer(sess, exploit.NewVerifier(canary), canary)
	scanCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	findings, err := fuzzer.FuzzURL(scanCtx, target)
	if err != nil {
		return err
	}

	// 6. Report.
	if len(findings) == 0 {
		p("\n✔  No confirmed vulnerabilities (zero false positives by design).\n")
		return nil
	}
	p("\n\033[1;31m!  %d CONFIRMED finding(s):\033[0m\n", len(findings))
	for i, f := range findings {
		p("\n  #%d %s [%s] via %s\n", i+1, f.Class, f.Severity, f.VerifiedVia)
		p("     param  : %s\n", f.Param)
		p("     payload: %s\n", f.Payload)
		for _, e := range f.Evidence {
			p("     · %s\n", e)
		}
	}
	return nil
}

// ask prints a prompt and returns a trimmed line of input.
func ask(r *bufio.Reader, out io.Writer, prompt string) string {
	fmt.Fprint(out, prompt)
	line, _ := r.ReadString('\n')
	return strings.TrimSpace(line)
}
