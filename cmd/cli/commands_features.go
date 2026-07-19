package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"os"
	"time"

	"github.com/security-life-org/DarkObscura/internal/access"
	"github.com/security-life-org/DarkObscura/internal/chain"
	"github.com/security-life-org/DarkObscura/internal/clientside"
	"github.com/security-life-org/DarkObscura/internal/dynamic"
	"github.com/security-life-org/DarkObscura/internal/engine"
	"github.com/security-life-org/DarkObscura/internal/evasion"
	"github.com/security-life-org/DarkObscura/internal/exploit"
	"github.com/security-life-org/DarkObscura/internal/fingerprint"
	"github.com/security-life-org/DarkObscura/internal/findings"
	"github.com/security-life-org/DarkObscura/internal/graphql"
	"github.com/security-life-org/DarkObscura/internal/report"
	"github.com/security-life-org/DarkObscura/internal/secrets"
	"github.com/spf13/cobra"
)

// featureCmds returns the subcommands for the ten precision features.
func featureCmds() []*cobra.Command {
	return []*cobra.Command{
		surfaceCmd(), idorCmd(), graphqlCmd(), evasionCmd(),
		secretsCmd(), clientsideCmd(), reportCmd(), chainCmd(),
		fingerprintCmd(),
	}
}

func authGate(cmd *cobra.Command) error {
	ack, _ := cmd.Flags().GetBool("i-have-authorization")
	if !ack {
		return fmt.Errorf("refusing: pass --i-have-authorization to confirm you are permitted to test the target")
	}
	return nil
}

func addAuthFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool("i-have-authorization", false, "confirm you are authorized to test the target")
	return cmd
}

// surfaceCmd — F1: dynamic/JS surface harvester.
func surfaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "surface <url>",
		Short: "F1: harvest dynamic attack surface (JS-mined endpoints/params/GraphQL/WS)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := authGate(cmd); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			s, err := dynamic.Harvest(ctx, args[0], dynamic.Options{})
			if err != nil {
				return err
			}
			fmt.Printf("[+] origin=%s scripts=%d\n", s.Origin, len(s.Scripts))
			printList("endpoints", s.Endpoints)
			printList("params", s.Params)
			printList("graphql", s.GraphQL)
			printList("websockets", s.WebSockets)
			printList("source-maps", s.SourceMaps)
			return nil
		},
	}
	return addAuthFlag(cmd)
}

// idorCmd — F2: IDOR/BOLA multi-identity.
func idorCmd() *cobra.Command {
	var ownerCookie, attackerCookie string
	cmd := &cobra.Command{
		Use:   "idor <url>",
		Short: "F2: test a URL for IDOR/BOLA across owner vs attacker identities",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := authGate(cmd); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			eng := access.New(nil)
			owner := access.Identity{Name: "owner", Headers: map[string]string{}}
			if ownerCookie != "" {
				owner.Headers["Cookie"] = ownerCookie
			}
			others := []access.Identity{{Name: "anonymous"}}
			if attackerCookie != "" {
				others = append(others, access.Identity{Name: "attacker", Headers: map[string]string{"Cookie": attackerCookie}})
			}
			f, err := eng.Probe(ctx, access.Target{URL: args[0], Method: http.MethodGet}, owner, others)
			if err != nil {
				return err
			}
			if f == nil {
				fmt.Println("[+] no access-control violation confirmed")
				return nil
			}
			fmt.Printf("[!] IDOR CONFIRMED: %q accessed %q's resource (sim=%.3f)\n", f.Violator, f.Owner, f.Similarity)
			for _, e := range f.Evidence {
				fmt.Println("    ·", e)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&ownerCookie, "owner-cookie", "", "Cookie header for the authorized (owner) identity")
	cmd.Flags().StringVar(&attackerCookie, "attacker-cookie", "", "Cookie header for a second (attacker) identity")
	return addAuthFlag(cmd)
}

// graphqlCmd — F4.
func graphqlCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "graphql <endpoint>",
		Short: "F4: audit a GraphQL endpoint (introspection, alias/batch abuse)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := authGate(cmd); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			c := graphql.NewClient(args[0], nil)
			fs, err := c.Audit(ctx)
			if err != nil {
				return err
			}
			if bf := c.BatchProbe(ctx, 10); bf != nil {
				fs = append(fs, *bf)
			}
			if len(fs) == 0 {
				fmt.Println("[+] no GraphQL issues confirmed")
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

// evasionCmd — F5.
func evasionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "evade <payload>",
		Short: "F5: generate WAF-evasion mutations of a payload",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, m := range evasion.Mutate(args[0]) {
				fmt.Printf("%-20s %s\n", m.Technique, m.Payload)
			}
			return nil
		},
	}
}

// secretsCmd — F9: scan a URL body for leaked secrets.
func secretsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secrets <url>",
		Short: "F9: fetch a URL and scan its body/JS for leaked secrets",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := authGate(cmd); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			s, err := dynamic.Harvest(ctx, args[0], dynamic.Options{})
			if err != nil {
				return err
			}
			// Re-fetch page + scripts through a simple client and scan each body.
			total := 0
			client := &http.Client{Timeout: 20 * time.Second}
			for _, u := range append([]string{args[0]}, s.Scripts...) {
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				body := make([]byte, 0)
				buf := make([]byte, 1<<20)
				for {
					n, e := resp.Body.Read(buf)
					body = append(body, buf[:n]...)
					if e != nil || len(body) > 8<<20 {
						break
					}
				}
				resp.Body.Close()
				for _, m := range secrets.Scan(body) {
					total++
					fmt.Printf("[!] %-26s [%s] %s  (H=%.2f)\n", m.Type, m.Severity, m.Redacted, m.Entropy)
				}
			}
			if total == 0 {
				fmt.Println("[+] no secrets detected")
			}
			return nil
		},
	}
	return addAuthFlag(cmd)
}

// clientsideCmd — F10.
func clientsideCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clientside <url>",
		Short: "F10: CORS / cache-poisoning / CSP checks",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := authGate(cmd); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			fs, err := clientside.New(nil).Scan(ctx, args[0])
			if err != nil {
				return err
			}
			if len(fs) == 0 {
				fmt.Println("[+] no client-side issues confirmed")
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

// reportCmd — F8: run a scan and emit SARIF or HTML.
func reportCmd() *cobra.Command {
	var format, out string
	cmd := &cobra.Command{
		Use:   "report <url>",
		Short: "F8: scan a URL and write a SARIF or HTML report",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := authGate(cmd); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			sess, err := engine.NewSession()
			if err != nil {
				return err
			}
			fz := exploit.NewFuzzer(sess, exploit.NewVerifier(nil), nil)
			fs, err := fz.FuzzURL(ctx, args[0])
			if err != nil {
				return err
			}
			var data []byte
			switch format {
			case "sarif":
				data, err = report.SARIF(fs, version)
			default:
				data = []byte(report.HTML(fs, "DarkObscura Report — "+args[0], version, time.Now()))
			}
			if err != nil {
				return err
			}
			if out == "" {
				fmt.Print(string(data))
				return nil
			}
			if err := os.WriteFile(out, data, 0o644); err != nil {
				return err
			}
			fmt.Printf("[+] wrote %d findings to %s (%s)\n", len(fs), out, format)
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "html", "report format: html | sarif")
	cmd.Flags().StringVar(&out, "out", "", "output file (default: stdout)")
	return addAuthFlag(cmd)
}

// chainCmd — F7: build attack chains from a findings JSON file (F6 history export
// or a scan dump). Also demonstrates the F6 findings store.
func chainCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "chain <findings.json>",
		Short: "F7: build deterministic attack chains from a findings JSON file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			var fs []exploit.Finding
			if err := json.Unmarshal(raw, &fs); err != nil {
				return fmt.Errorf("parse findings json: %w", err)
			}
			if dbPath != "" {
				st, err := findings.Open(dbPath)
				if err != nil {
					return err
				}
				defer st.Close()
				var recs []findings.Record
				for _, f := range fs {
					recs = append(recs, findings.Record{
						Target: f.Target, Param: f.Param, Class: f.Class,
						Severity: string(f.Severity), Payload: f.Payload, VerifiedVia: f.VerifiedVia,
					})
				}
				fresh, err := st.Upsert(recs)
				if err != nil {
					return err
				}
				fmt.Printf("[+] %d finding(s), %d new since last scan\n", len(fs), len(fresh))
			}
			chains := chain.Build(fs)
			if len(chains) == 0 {
				fmt.Println("[+] no escalation chains derivable from these findings")
				return nil
			}
			for _, c := range chains {
				fmt.Print(chain.Render(c))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "optional findings SQLite DB for cross-scan dedup/history (F6)")
	return cmd
}

// fingerprintCmd — passive CMS / web-technology detection with confidence grading.
func fingerprintCmd() *cobra.Command {
	var confirmedOnly bool
	cmd := &cobra.Command{
		Use:   "fingerprint <url>",
		Short: "Identify CMS / framework / server / CDN tech (confidence-graded; --confirmed for zero-FP only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := authGate(cmd); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, args[0], nil)
			if err != nil {
				return err
			}
			req.Header.Set("User-Agent", "DarkObscura/fingerprint")
			resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
			if err != nil {
				return err
			}
			body := make([]byte, 0, 1<<16)
			buf := make([]byte, 1<<16)
			for {
				n, e := resp.Body.Read(buf)
				body = append(body, buf[:n]...)
				if e != nil || len(body) > 4<<20 {
					break
				}
			}
			resp.Body.Close()
			path := "/"
			if u, e := neturl.Parse(args[0]); e == nil {
				path = u.Path
			}
			techs := fingerprint.Detect(resp.Header, body, path)
			if confirmedOnly {
				techs = fingerprint.ConfirmedOnly(techs)
			}
			if len(techs) == 0 {
				fmt.Println("[+] no technologies identified")
				return nil
			}
			for _, t := range techs {
				ver := ""
				if t.Version != "" {
					ver = " " + t.Version
				}
				fmt.Printf("[%-9s] %-20s %-12s%s  (%s)\n", t.Confidence, t.Name, t.Category, ver, t.Evidence)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&confirmedOnly, "confirmed", false, "show only deterministically-confirmed technologies (zero false positives)")
	return addAuthFlag(cmd)
}

func printList(label string, items []string) {
	fmt.Printf("--- %s (%d) ---\n", label, len(items))
	for _, it := range items {
		fmt.Println("  ", it)
	}
}
