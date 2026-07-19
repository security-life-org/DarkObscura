package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/security-life-org/DarkObscura/internal/blindxss"
	"github.com/security-life-org/DarkObscura/internal/engine"
	"github.com/security-life-org/DarkObscura/internal/exploit"
	"github.com/security-life-org/DarkObscura/internal/findings"
	"github.com/security-life-org/DarkObscura/internal/liveaudit"
	"github.com/security-life-org/DarkObscura/internal/logicflow"
	"github.com/security-life-org/DarkObscura/internal/payloads"
	"github.com/security-life-org/DarkObscura/internal/proxy"
	"github.com/security-life-org/DarkObscura/pkg/certgen"
	"github.com/spf13/cobra"
)

// gameChangerCmds returns the three headline capabilities plus the payload
// generator.
func gameChangerCmds() []*cobra.Command {
	return []*cobra.Command{liveauditCmd(), blindxssCmd(), logicCmd(), payloadsCmd()}
}

// liveauditCmd — Game-changer #1: always-on passive audit from the MITM proxy.
func liveauditCmd() *cobra.Command {
	var addr, certDir, dbPath, canaryZone, canaryDNS, canaryHTTP string
	cmd := &cobra.Command{
		Use:   "liveaudit",
		Short: "GC1: always-on passive audit — browse through the proxy, get live confirmed findings",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := authGate(cmd); err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			ca, err := certgen.LoadOrCreate(certDir)
			if err != nil {
				return fmt.Errorf("load CA: %w", err)
			}
			var canary *exploit.CanaryServer
			if canaryZone != "" {
				canary = exploit.NewCanaryServer(canaryZone, nil)
				go canary.ListenAndServe(ctx, canaryDNS, canaryHTTP)
			}
			var store *findings.Store
			if dbPath != "" {
				store, err = findings.Open(dbPath)
				if err != nil {
					return err
				}
				defer store.Close()
			}
			auditor := liveaudit.New(ctx, liveaudit.Options{
				Canary: canary, Store: store,
				OnFinding: func(f exploit.Finding) {
					fmt.Printf("\n[!] LIVE FINDING: %s [%s] %s param=%s via %s\n",
						f.Class, f.Severity, f.Target, f.Param, f.VerifiedVia)
					for _, e := range f.Evidence {
						fmt.Println("    ·", e)
					}
				},
			})
			p := proxy.New(proxy.Options{CA: ca, Logger: nil})
			p.Use(auditor)

			fmt.Printf("[*] live-audit proxy on %s\n", addr)
			fmt.Printf("[*] set your browser HTTP/HTTPS proxy to %s and trust the CA in %s\n", addr, certDir)
			fmt.Println("[*] browse the target normally; new parameterized endpoints are audited automatically")
			return p.ListenAndServe(ctx, addr)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8080", "proxy listen address")
	cmd.Flags().StringVar(&certDir, "cert-dir", "./dobscura-ca", "directory for the MITM root CA")
	cmd.Flags().StringVar(&dbPath, "db", "", "findings SQLite DB for cross-scan dedup (only new bugs surface)")
	cmd.Flags().StringVar(&canaryZone, "canary-zone", "", "OOB canary DNS zone (enables SSRF/RCE confirmation)")
	cmd.Flags().StringVar(&canaryDNS, "canary-dns", ":53", "canary DNS listen address")
	cmd.Flags().StringVar(&canaryHTTP, "canary-http", ":8081", "canary HTTP listen address")
	return addAuthFlag(cmd)
}

// blindxssCmd — Game-changer #2: stored/blind XSS via persistent OOB beacons.
func blindxssCmd() *cobra.Command {
	var params, location, canaryZone, canaryDNS, canaryHTTP string
	var wait time.Duration
	cmd := &cobra.Command{
		Use:   "blindxss <url>",
		Short: "GC2: spray canary beacons for stored/blind XSS and watch for out-of-band callbacks",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := authGate(cmd); err != nil {
				return err
			}
			if canaryZone == "" {
				return fmt.Errorf("--canary-zone is required (beacons need an OOB listener to confirm)")
			}
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			canary := exploit.NewCanaryServer(canaryZone, nil)
			go canary.ListenAndServe(ctx, canaryDNS, canaryHTTP)

			sess, err := engine.NewSession()
			if err != nil {
				return err
			}
			reg := blindxss.NewRegistry()
			sprayer := blindxss.NewSprayer(sess, canary, reg)
			target := blindxss.Target{URL: args[0], Params: splitCSV(params), Location: location}
			n, err := sprayer.Spray(ctx, []blindxss.Target{target})
			if err != nil {
				return err
			}
			fmt.Printf("[*] planted %d beacon(s); watching %s for callbacks (Ctrl+C to stop)\n", n, wait)
			blindxss.Watch(ctx, canary, reg, 3*time.Second, wait, func(f exploit.Finding) {
				fmt.Printf("\n[!] STORED/BLIND XSS CONFIRMED: %s param=%s\n", f.Target, f.Param)
				for _, e := range f.Evidence {
					fmt.Println("    ·", e)
				}
			})
			fmt.Println("[*] watch window elapsed")
			return nil
		},
	}
	cmd.Flags().StringVar(&params, "params", "", "comma-separated field names to inject beacons into")
	cmd.Flags().StringVar(&location, "location", "query", "injection location: query | form")
	cmd.Flags().StringVar(&canaryZone, "canary-zone", "", "OOB canary DNS zone (required)")
	cmd.Flags().StringVar(&canaryDNS, "canary-dns", ":53", "canary DNS listen address")
	cmd.Flags().StringVar(&canaryHTTP, "canary-http", ":8081", "canary HTTP listen address")
	cmd.Flags().DurationVar(&wait, "wait", 2*time.Minute, "how long to watch for beacon callbacks")
	return addAuthFlag(cmd)
}

// logicCmd — Game-changer #3: business-logic state-machine testing.
func logicCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logic <flow.json>",
		Short: "GC3: run a business-logic flow spec and test tampering/invariants",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := authGate(cmd); err != nil {
				return err
			}
			raw, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			var flow logicflow.Flow
			if err := json.Unmarshal(raw, &flow); err != nil {
				return fmt.Errorf("parse flow json: %w", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			fs, err := logicflow.NewRunner(nil).Run(ctx, flow)
			if err != nil {
				return err
			}
			if len(fs) == 0 {
				fmt.Println("[+] no business-logic issues confirmed")
				return nil
			}
			for _, f := range fs {
				fmt.Printf("[!] %s [%s]: %s\n", f.Class, f.Severity, f.Detail)
				for _, e := range f.Evidence {
					fmt.Println("    ·", e)
				}
			}
			return nil
		},
	}
	return addAuthFlag(cmd)
}

// payloadsCmd — the multi-situation payload generator.
func payloadsCmd() *cobra.Command {
	var oobHost string
	cmd := &cobra.Command{
		Use:   "payloads <class> [context]",
		Short: "Generate context-aware payloads for a class (xss/sqli/ssti/lfi/nosqli/cmdi/redirect/ssrf)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			class := args[0]
			ctxName := payloads.CtxAny
			if len(args) == 2 {
				ctxName = payloads.Context(args[1])
			}
			var ps []payloads.Payload
			switch class {
			case "ssrf":
				ps = payloads.SSRFTargets(oobHost)
			default:
				ps = payloads.Generate(class, ctxName, "01")
				if len(ps) == 0 {
					ps = payloads.ForFinding(class, "01", oobHost)
				}
			}
			if len(ps) == 0 {
				return fmt.Errorf("no payloads for class %q", class)
			}
			for _, p := range ps {
				fmt.Printf("[%s/%s oracle=%s sev=%s] %s\n", p.Class, p.Context, p.Oracle, p.Severity, p.Value)
				if p.Marker != "" {
					fmt.Printf("    marker=%q\n", p.Marker)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&oobHost, "oob-host", "", "canary host for OOB-confirmed payloads (ssrf/cmdi)")
	return cmd
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
