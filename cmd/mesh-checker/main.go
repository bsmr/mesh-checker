// Command mesh-checker probes ICMP, TCP, and UDP reachability between mesh peers.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/bsmr/mesh-checker/internal/pkg/checker"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
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
