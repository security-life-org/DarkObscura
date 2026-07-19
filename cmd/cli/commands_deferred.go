package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/security-life-org/DarkObscura/internal/dom"
	"github.com/security-life-org/DarkObscura/internal/grpcfuzz"
	"github.com/security-life-org/DarkObscura/internal/sourcemap"
	"github.com/security-life-org/DarkObscura/internal/wsfuzz"
	"github.com/spf13/cobra"
)

func deferredCmds() []*cobra.Command {
	return []*cobra.Command{domCmd(), sourcemapCmd(), wsfuzzCmd(), grpcCmd()}
}

// grpcCmd — enumerate and fuzz a gRPC endpoint via server reflection.
func grpcCmd() *cobra.Command {
	var useTLS, enumOnly bool
	cmd := &cobra.Command{
		Use:   "grpc <host:port>",
		Short: "Enumerate & fuzz a gRPC service via server reflection (no .proto needed)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := authGate(cmd); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			var res *grpcfuzz.Result
			var err error
			if enumOnly {
				res, err = grpcfuzz.Enumerate(ctx, args[0], useTLS)
			} else {
				res, err = grpcfuzz.Fuzz(ctx, args[0], useTLS)
			}
			if err != nil {
				return err
			}
			fmt.Printf("[+] %d service(s) discovered via reflection\n", len(res.Services))
			for _, s := range res.Services {
				fmt.Printf("  service %s\n", s.Name)
				for _, m := range s.Methods {
					st := ""
					if m.InvokeStatus != "" {
						st = "  → " + m.InvokeStatus
					}
					kind := "unary"
					if m.ClientStream || m.ServerStream {
						kind = "stream"
					}
					fmt.Printf("    · %s (%s)%s\n", m.Name, kind, st)
				}
			}
			for _, f := range res.Findings {
				fmt.Printf("[!] %s [%s]: %s\n", f.Class, f.Confidence, f.Detail)
				for _, e := range f.Evidence {
					fmt.Println("    ·", e)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&useTLS, "tls", false, "use TLS (for grpcs endpoints)")
	cmd.Flags().BoolVar(&enumOnly, "enumerate-only", false, "list services/methods without invoking them")
	return addAuthFlag(cmd)
}

// domCmd — client-side DOM analysis (static always; dynamic if built -tags chromedp).
func domCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dom <url>",
		Short: "Analyze the client-side DOM for possible DOM-XSS sinks/sources (headless with -tags chromedp)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := authGate(cmd); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()

			_, body, _, err := fetchBody(ctx, args[0])
			if err != nil {
				return err
			}
			fmt.Println("── static analysis ──")
			printDOM(dom.Analyze(body))

			if dom.Available() {
				fmt.Println("\n── headless (rendered DOM) ──")
				r, err := dom.Render(ctx, args[0])
				if err != nil {
					fmt.Println("[!] render failed:", err)
					return nil
				}
				printDOM(dom.Analyze([]byte(r.HTML)))
				fmt.Printf("\n── runtime endpoints (%d) ──\n", len(r.Endpoints))
				for _, e := range r.Endpoints {
					fmt.Println("  ", e)
				}
			} else {
				fmt.Println("\n[i] headless renderer not compiled in — rebuild with `-tags chromedp` (needs local Chrome) for dynamic DOM + runtime endpoints")
			}
			return nil
		},
	}
	return addAuthFlag(cmd)
}

func printDOM(fs []dom.Finding) {
	if len(fs) == 0 {
		fmt.Println("  (nothing notable)")
		return
	}
	for _, f := range fs {
		loc := f.Sink
		if f.Source != "" {
			loc = f.Source + " → " + f.Sink
		}
		fmt.Printf("  [%s] %s %s\n     %s\n", f.Confidence, f.Class, loc, f.Evidence)
	}
}

// sourcemapCmd — reconstruct original source from a leaked .map and scan it.
func sourcemapCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sourcemap <url-or-file>",
		Short: "Reconstruct original source from a leaked .map (or a .js's sourceMappingURL) and scan it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := authGate(cmd); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()

			var res *sourcemap.Result
			var err error
			if fileExists(args[0]) {
				var data []byte
				if data, err = os.ReadFile(args[0]); err == nil {
					res, err = sourcemap.Parse(data)
				}
			} else {
				res, err = sourcemap.FetchAndReconstruct(ctx, nil, args[0])
			}
			if err != nil {
				return err
			}
			fmt.Printf("[+] reconstructed %d source file(s), %d secret(s), %d endpoint(s)\n",
				len(res.Sources), len(res.Secrets), len(res.Endpoints))
			for _, s := range res.Secrets {
				fmt.Printf("[!] secret %s [%s]: %s (H=%.2f)\n", s.Type, s.Severity, s.Redacted, s.Entropy)
			}
			printList("endpoints", res.Endpoints)
			if len(res.Sources) > 0 {
				fmt.Println("recovered files:")
				for _, s := range res.Sources {
					fmt.Println("  ", s.Path)
				}
			}
			return nil
		},
	}
	return addAuthFlag(cmd)
}

// wsfuzzCmd — fuzz a WebSocket endpoint.
func wsfuzzCmd() *cobra.Command {
	var template, origin string
	cmd := &cobra.Command{
		Use:   "wsfuzz <ws-url>",
		Short: "Fuzz a WebSocket endpoint for reflected input and SQL injection (FUZZ marks the injection slot)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := authGate(cmd); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			f := wsfuzz.New(args[0], template)
			f.Origin = origin
			fs, err := f.Run(ctx)
			if err != nil {
				return err
			}
			if len(fs) == 0 {
				fmt.Println("[+] no WebSocket issues found")
				return nil
			}
			for _, x := range fs {
				fmt.Printf("[!] %s [%s]\n", x.Class, x.Confidence)
				for _, e := range x.Evidence {
					fmt.Println("    ·", e)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&template, "template", "FUZZ", "message template; the literal FUZZ is replaced with each payload")
	cmd.Flags().StringVar(&origin, "origin", "", "Origin header to present on the handshake")
	return addAuthFlag(cmd)
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
