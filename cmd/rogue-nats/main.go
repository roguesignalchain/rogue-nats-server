package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/roguesignalchain/rogue-nats-server/internal/config"
	"github.com/roguesignalchain/rogue-nats-server/internal/server"
)

// Version is injected at build time via -ldflags.
var Version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "serve error: %v\n", err)
			os.Exit(1)
		}
	case "version":
		fmt.Printf("rogue-nats %s\n", Version)
	default:
		printUsage()
		os.Exit(1)
	}
}

func runServe(args []string) error {
	cfg := config.Default()
	cfg.ApplyEnv()

	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.StringVar(&cfg.Host, "host", cfg.Host, "Bind host address")
	fs.IntVar(&cfg.Port, "port", cfg.Port, "NATS TCP port")
	fs.IntVar(&cfg.WSPort, "ws-port", cfg.WSPort, "NATS WebSocket port")
	fs.IntVar(&cfg.HTTPPort, "http-port", cfg.HTTPPort, "Monitoring HTTP port (/healthz, /varz, /jsz)")
	fs.StringVar(&cfg.DataDir, "data-dir", cfg.DataDir, "Data directory for JetStream and NKeys")
	fs.StringVar(&cfg.RPCURL, "rpc-url", cfg.RPCURL, "Rogue Signal JSON-RPC endpoint")
	fs.Uint64Var(&cfg.LookbackBlocks, "lookback-blocks", cfg.LookbackBlocks, "Minimum balance age in blocks")
	fs.StringVar(&cfg.TLSCert, "tls-cert", cfg.TLSCert, "Path to TLS certificate")
	fs.StringVar(&cfg.TLSKey, "tls-key", cfg.TLSKey, "Path to TLS private key")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Log level (debug, info, warn, error)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := newJSONLogger(cfg.LogLevel)
	srv, err := server.New(cfg, logger)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Start(ctx); err != nil {
		return err
	}

	<-ctx.Done()
	logger.Info("shutting down rogue-nats-server")
	srv.Shutdown()
	return nil
}

func newJSONLogger(levelStr string) *slog.Logger {
	level := slog.LevelInfo
	switch levelStr {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: rogue-nats <command> [flags]\n\nCommands:\n  serve     Start the Rogue Signal NATS + JetStream server\n  version   Print version information\n")
}
