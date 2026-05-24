// Package cli wires the mesh-checker command-line interface to the checker
// service. It parses flags, assembles a checker.Config, and delegates to
// checker.ServiceData. Kept separate from package main so the CLI can be
// unit-tested without invoking os.Exit.
package cli

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/bsmr/mesh-checker/internal/pkg/checker"
)

// Run is the CLI entry point. It installs a SIGINT/SIGTERM handler on ctx,
// parses args, and invokes the checker service. main() should call this
// and translate the returned error into an exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	fs := flag.NewFlagSet("mesh-checker", flag.ContinueOnError)
	fs.SetOutput(stderr)
	peersFlag := fs.String("peers", "", "comma-separated list of peer addresses to probe")

	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := checker.Config{Peers: splitPeers(*peersFlag)}

	svc := &checker.ServiceData{Stdout: stdout, Stderr: stderr}
	if err := svc.Run(ctx, cfg); err != nil {
		if errors.Is(err, checker.ErrNoPeers) {
			fs.Usage()
		}
		return err
	}
	return nil
}

// splitPeers parses a comma-separated peer list, trimming whitespace and
// dropping empty entries. Returns nil for an empty input so callers can
// distinguish "no peers" from "empty slice".
func splitPeers(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
