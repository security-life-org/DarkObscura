// Command core is the DarkObscura backend daemon: it boots the MITM proxy,
// storage, and (optionally) the OOB canary server, wiring interceptors together.
//
// AUTHORIZED USE ONLY. DarkObscura is offensive security tooling. Run it only
// against systems you own or are explicitly authorized to test.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/security-life-org/DarkObscura/internal/proxy"
	"github.com/security-life-org/DarkObscura/internal/storage"
	"github.com/security-life-org/DarkObscura/pkg/certgen"
)

func main() {
	var (
		addr    = flag.String("addr", ":8080", "proxy listen address")
		dataDir = flag.String("data", defaultDataDir(), "data directory (CA, storage)")
		verbose = flag.Bool("v", false, "verbose logging")
		ackAuth = flag.Bool("i-have-authorization", false, "acknowledge you are authorized to test the targets")
	)
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if !*ackAuth {
		log.Error("refusing to start: pass --i-have-authorization to confirm you are authorized to test the target systems")
		os.Exit(2)
	}

	ca, err := certgen.LoadOrCreate(filepath.Join(*dataDir, "ca"))
	if err != nil {
		log.Error("ca init failed", "err", err)
		os.Exit(1)
	}
	log.Info("root CA ready", "trust_file", filepath.Join(*dataDir, "ca", "ca.crt"))

	store, err := storage.Open(filepath.Join(*dataDir, "store"))
	if err != nil {
		log.Error("storage open failed", "err", err)
		os.Exit(1)
	}
	defer store.Close()

	px := proxy.New(proxy.Options{CA: ca, Store: store, Logger: log})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := px.ListenAndServe(ctx, *addr); err != nil {
		log.Error("proxy stopped with error", "err", err)
		os.Exit(1)
	}
	log.Info("shutdown complete")
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".darkobscura"
	}
	return filepath.Join(home, ".darkobscura")
}
