package main

import (
	"context"
	"fmt"
	"net/http"
	neturl "net/url"
	"os"
	"time"

	"github.com/security-life-org/DarkObscura/internal/cve"
	"github.com/security-life-org/DarkObscura/internal/engine"
	"github.com/security-life-org/DarkObscura/internal/exploit"
	"github.com/security-life-org/DarkObscura/internal/fingerprint"
	"github.com/security-life-org/DarkObscura/internal/findings"
	"github.com/security-life-org/DarkObscura/internal/harimport"
	"github.com/security-life-org/DarkObscura/internal/jwtattack"
	"github.com/security-life-org/DarkObscura/internal/takeover"
	"github.com/security-life-org/DarkObscura/internal/templates"
	"github.com/security-life-org/DarkObscura/internal/waf"
	"github.com/spf13/cobra"
)

func nextCmds() []*cobra.Command {
	return []*cobra.Command{cveCmd(), templatesCmd(), harimportCmd(), takeoverCmd(), jwtCmd(), ciCmd(), wafCmd()}
}

// wafCmd — actively probe whether a WAF is present and blocking attack traffic.
func wafCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "waf <url>",
		Short: "Detect a WAF and whether it BLOCKS attack traffic (so empty results aren't mistaken for 'safe')",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := authGate(cmd); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			res, err := waf.Probe(ctx, nil, args[0])
			if err != nil {
				return err
			}
			fmt.Printf("[*] WAF: %s · present=%v · blocks-attacks=%v · baseline-blocked=%v\n",
				orNone(res.WAF), res.Present, res.BlocksAttack, res.Baseline.Blocked)
			for _, e := range res.Evidence {
				fmt.Println("    ·", e)
			}
			return nil
		},
	}
	return addAuthFlag(cmd)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func fetchBody(ctx context.Context, url string) (http.Header, []byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, "", err
	}
	req.Header.Set("User-Agent", "DarkObscura")
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, nil, "", err
	}
	defer resp.Body.Close()
	body := make([]byte, 0, 1<<16)
	buf := make([]byte, 1<<16)
	for {
		n, e := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if e != nil || len(body) > 4<<20 {
			break
		}
	}
	path := "/"
	if u, e := neturl.Parse(url); e == nil {
		path = u.Path
	}
	return resp.Header, body, path, nil
}

// cveCmd — fingerprint a target then correlate confirmed versions to known CVEs.
func cveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cve <url>",
		Short: "Correlate confirmed technology versions to known CVEs (zero-FP: version-range match)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := authGate(cmd); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			hdr, body, path, err := fetchBody(ctx, args[0])
			if err != nil {
				return err
			}
			techs := fingerprint.Detect(hdr, body, path)
			vulns := cve.Correlate(techs)
			if len(vulns) == 0 {
				fmt.Println("[+] no CVEs matched the confirmed technology versions")
				return nil
			}
			for _, v := range vulns {
				fmt.Printf("[!] %s [%s] %s %s — %s\n    %s\n    ref: %s\n",
					v.ID, v.Severity, v.Tech, v.Version, v.Title, v.Evidence, v.Reference)
			}
			return nil
		},
	}
	return addAuthFlag(cmd)
}

// templatesCmd — run Nuclei-compatible YAML templates against a target.
func templatesCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "templates <url>",
		Short: "Run built-in + Nuclei-compatible YAML templates against a target",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := authGate(cmd); err != nil {
				return err
			}
			tmpls, err := templates.Builtin()
			if err != nil {
				return err
			}
			if dir != "" {
				loaded, err := templates.LoadDir(dir)
				if err != nil {
					return err
				}
				tmpls = append(tmpls, loaded...)
			}
			eng := templates.New(tmpls)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			fmt.Printf("[*] running %d templates against %s\n", eng.Count(), args[0])
			hits, err := eng.Run(ctx, args[0])
			if err != nil {
				return err
			}
			if len(hits) == 0 {
				fmt.Println("[+] no template matched")
				return nil
			}
			for _, h := range hits {
				fmt.Printf("[!] %s [%s] %s — %s (%s)\n", h.TemplateID, h.Severity, h.Name, h.Matched, h.URL)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "directory of extra .yaml/.yml templates (Nuclei-compatible)")
	return addAuthFlag(cmd)
}

// harimportCmd — turn a recorded browser HAR into endpoints + auth material.
func harimportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "harimport <file.har>",
		Short: "Import a recorded browser session (HAR) → endpoints + captured auth (cookies/bearer)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			res, err := harimport.Parse(raw)
			if err != nil {
				return err
			}
			fmt.Printf("[+] %d requests · %d endpoints · %d hosts\n", res.Requests, len(res.Endpoints), len(res.Hosts))
			if res.BearerToken != "" {
				fmt.Printf("[+] captured bearer token: %s…\n", truncStr(res.BearerToken, 24))
			}
			if len(res.Cookies) > 0 {
				fmt.Printf("[+] captured %d cookie(s); Cookie header: %s\n", len(res.Cookies), truncStr(res.CookieHeader(), 80))
			}
			printList("endpoints", res.Endpoints)
			return nil
		},
	}
	return cmd
}

// takeoverCmd — check a host for subdomain takeover.
func takeoverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "takeover <host>",
		Short: "Check a host for subdomain takeover (confirmed only: dangling CNAME + provider signature)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := authGate(cmd); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			f, err := takeover.New().Check(ctx, args[0])
			if err != nil {
				return fmt.Errorf("resolve/check: %w", err)
			}
			if f == nil {
				fmt.Println("[+] no takeover confirmed")
				return nil
			}
			fmt.Printf("[!] SUBDOMAIN TAKEOVER [%s]: %s → %s (%s)\n", f.Severity, f.Host, f.CNAME, f.Provider)
			for _, e := range f.Evidence {
				fmt.Println("    ·", e)
			}
			return nil
		},
	}
	return addAuthFlag(cmd)
}

// jwtCmd — analyze/attack a JWT.
func jwtCmd() *cobra.Command {
	var forge bool
	cmd := &cobra.Command{
		Use:   "jwt <token>",
		Short: "Analyze a JWT for alg=none and weak HS256 secrets (crack is cryptographic proof)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := jwtattack.Decode(args[0])
			if err != nil {
				return err
			}
			fmt.Printf("[*] alg=%s claims=%v\n", t.Alg, t.Claims)
			fs := jwtattack.Analyze(t, nil)
			if len(fs) == 0 {
				fmt.Println("[+] no JWT weakness confirmed")
			}
			for _, f := range fs {
				fmt.Printf("[!] %s [%s]: %s\n", f.Class, f.Severity, f.Detail)
				for _, e := range f.Evidence {
					fmt.Println("    ·", e)
				}
			}
			if forge {
				fmt.Println("[*] forged alg=none token (admin=true):")
				fmt.Println("   ", jwtattack.ForgeNone(t, map[string]any{"admin": true}))
				if secret, ok := jwtattack.Crack(t, jwtattack.DefaultSecrets); ok {
					fmt.Println("[*] forged HS256 token re-signed with cracked secret:")
					fmt.Println("   ", jwtattack.ForgeHS256(t, secret, map[string]any{"admin": true}))
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&forge, "forge", false, "also print forged tokens (alg=none and, if cracked, HS256)")
	return cmd
}

// ciCmd — CI/CD gate: scan, store, exit non-zero if there are NEW findings.
func ciCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "ci <url>",
		Short: "CI gate: scan a URL, dedup against history, exit non-zero on NEW findings",
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
			found, err := fz.FuzzURL(ctx, args[0])
			if err != nil {
				return err
			}
			var fresh []findings.Record
			if dbPath != "" {
				st, err := findings.Open(dbPath)
				if err != nil {
					return err
				}
				defer st.Close()
				var recs []findings.Record
				for _, f := range found {
					recs = append(recs, findings.Record{
						Target: f.Target, Param: f.Param, Class: f.Class,
						Severity: string(f.Severity), Payload: f.Payload, VerifiedVia: f.VerifiedVia,
					})
				}
				fresh, err = st.Upsert(recs)
				if err != nil {
					return err
				}
			} else {
				for _, f := range found {
					fresh = append(fresh, findings.Record{Target: f.Target, Param: f.Param, Class: f.Class, Severity: string(f.Severity)})
				}
			}
			fmt.Printf("[ci] %d confirmed finding(s), %d NEW\n", len(found), len(fresh))
			for _, r := range fresh {
				fmt.Printf("  NEW %s [%s] %s param=%s\n", r.Class, r.Severity, r.Target, r.Param)
			}
			if len(fresh) > 0 {
				os.Exit(2) // fail the pipeline
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "", "findings SQLite DB for cross-run dedup (only NEW findings fail the build)")
	return addAuthFlag(cmd)
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
