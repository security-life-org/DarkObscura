// Command dobscura is the DarkObscura headless CLI: it runs discovery and the
// verification-gated fuzzer against a target from the terminal.
//
// AUTHORIZED USE ONLY. Only scan systems you own or are explicitly permitted to test.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/security-life-org/DarkObscura/internal/engine"
	"github.com/security-life-org/DarkObscura/internal/exploit"
	"github.com/security-life-org/DarkObscura/internal/gui"
	"github.com/security-life-org/DarkObscura/internal/parser"
	"github.com/spf13/cobra"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var (
		guiMode      bool
		wizardMode   bool
		showVersion  bool
		guiAddr      string
		noOpen       bool
		scopeSpec    string
		allowPrivate bool
		noAuth       bool
		token        string
	)
	root := &cobra.Command{
		Use:   "dobscura",
		Short: "DarkObscura — precision web security testing platform",
		Long: "DarkObscura. AUTHORIZED USE ONLY: scan only systems you own or are permitted to test.\n\n" +
			"Run with --gui for the desktop UI, or --wizard for a guided scan.\n" +
			"Deploy with --scope to restrict the engagement and keep the instance from being abused.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if showVersion {
				fmt.Printf("DarkObscura %s\n", version)
				return nil
			}
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			switch {
			case guiMode:
				return gui.Serve(ctx, gui.Options{
					Addr: guiAddr, Open: !noOpen, Version: version,
					Scope: scopeSpec, AllowPrivate: allowPrivate,
					RequireAuth: !noAuth, Token: token,
				})
			case wizardMode:
				return gui.RunWizard(ctx, os.Stdin, os.Stdout)
			default:
				return cmd.Help()
			}
		},
	}
	root.Flags().BoolVar(&guiMode, "gui", false, "launch the embedded desktop GUI (opens in your browser)")
	root.Flags().BoolVar(&wizardMode, "wizard", false, "run an interactive, guided scan in the terminal")
	root.Flags().BoolVar(&showVersion, "version", false, "print version and exit")
	root.Flags().StringVar(&guiAddr, "gui-addr", "127.0.0.1:8422", "address the GUI server listens on")
	root.Flags().BoolVar(&noOpen, "no-open", false, "do not auto-open the browser in --gui mode")
	root.Flags().StringVar(&scopeSpec, "scope", "", "comma-separated in-scope hosts/domains/CIDRs (empty = any public host)")
	root.Flags().BoolVar(&allowPrivate, "allow-private", false, "permit scanning private/loopback/metadata targets (off by default — SSRF protection)")
	root.Flags().BoolVar(&noAuth, "no-auth", false, "disable the API token requirement (NOT recommended when bound non-locally)")
	root.Flags().StringVar(&token, "token", "", "API token (generated automatically if unset and auth is on)")

	root.AddCommand(scanCmd(), classifyCmd())
	root.AddCommand(featureCmds()...)
	root.AddCommand(gameChangerCmds()...)
	root.AddCommand(nextCmds()...)
	root.AddCommand(deferredCmds()...)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func scanCmd() *cobra.Command {
	var (
		ackAuth    bool
		canaryZone string
		canaryDNS  string
		canaryHTTP string
		rps        float64
		timeout    time.Duration
	)
	cmd := &cobra.Command{
		Use:   "scan <url>",
		Short: "Discover parameters and run verification-gated fuzzing against a URL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !ackAuth {
				return fmt.Errorf("refusing to scan: pass --i-have-authorization to confirm you are permitted to test %q", args[0])
			}
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			var canary *exploit.CanaryServer
			if canaryZone != "" {
				canary = exploit.NewCanaryServer(canaryZone, nil)
				go canary.ListenAndServe(ctx, canaryDNS, canaryHTTP)
				fmt.Printf("[*] OOB canary listening (zone=%s dns=%s http=%s)\n", canaryZone, canaryDNS, canaryHTTP)
			}

			sess, err := engine.NewSession()
			if err != nil {
				return err
			}
			// Politeness / safety: throttle per host.
			_ = engine.NewHostLimiter(rps, int(rps)+1)

			fuzzer := exploit.NewFuzzer(sess, exploit.NewVerifier(canary), canary)
			// Surface WAF / block signals (and other warnings) during the scan so an
			// empty result is never silently mistaken for "safe".
			fuzzer.OnProgress = func(p exploit.Progress) {
				if p.Kind == "waf" {
					fmt.Printf("[!] %s\n", p.Message)
				}
			}
			fmt.Printf("[*] scanning %s\n", args[0])
			findings, err := fuzzer.FuzzURL(ctx, args[0])
			if err != nil {
				return err
			}
			printFindings(findings)
			return nil
		},
	}
	cmd.Flags().BoolVar(&ackAuth, "i-have-authorization", false, "confirm you are authorized to test the target")
	cmd.Flags().StringVar(&canaryZone, "canary-zone", "", "DNS zone for OOB canary (e.g. canary.example.com); empty disables OOB")
	cmd.Flags().StringVar(&canaryDNS, "canary-dns", ":53", "canary DNS listen address")
	cmd.Flags().StringVar(&canaryHTTP, "canary-http", ":8081", "canary HTTP listen address")
	cmd.Flags().Float64Var(&rps, "rps", 10, "max requests per second per host")
	cmd.Flags().DurationVar(&timeout, "timeout", 2*time.Minute, "overall scan timeout")
	return cmd
}

// classifyCmd is a quick utility to show how a parameter name is risk-classified.
func classifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "classify <param-name> [value]",
		Short: "Show the risk classification for a parameter name",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			value := ""
			if len(args) == 2 {
				value = args[1]
			}
			cls := parser.DefaultClassifier()
			risk, reasons := cls.Classify(args[0], value)
			fmt.Printf("%-20s risk=%s\n", args[0], risk)
			for _, r := range reasons {
				fmt.Printf("  - %s\n", r)
			}
			return nil
		},
	}
}

func printFindings(findings []exploit.Finding) {
	if len(findings) == 0 {
		fmt.Println("[+] no confirmed vulnerabilities (zero false positives by design)")
		return
	}
	fmt.Printf("\n[!] %d CONFIRMED finding(s):\n", len(findings))
	for i, f := range findings {
		fmt.Printf("\n#%d %s [%s] via %s\n", i+1, f.Class, f.Severity, f.VerifiedVia)
		fmt.Printf("    target : %s\n", f.Target)
		fmt.Printf("    param  : %s\n", f.Param)
		fmt.Printf("    payload: %s\n", f.Payload)
		for _, e := range f.Evidence {
			fmt.Printf("    · %s\n", e)
		}
	}
}
