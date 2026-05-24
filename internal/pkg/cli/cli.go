// Package cli wires the mesh-checker subcommands. Run dispatches to a
// handler registered by name; handlers parse their own flags. Kept
// separate from package main so it can be tested without os.Exit.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"syscall"
)

// Handler is the contract every subcommand fulfils.
type Handler func(ctx context.Context, args []string, stdout, stderr io.Writer) error

type subcommand struct {
	summary string
	run     Handler
}

var subcommands = map[string]subcommand{}

// register adds a subcommand to the dispatcher. It MUST only be called
// from package-level init() functions. Calling it concurrently with
// Run, or after program startup, is a data race on the subcommands map.
func register(name, summary string, run Handler) {
	if _, dup := subcommands[name]; dup {
		panic("cli: duplicate subcommand " + name)
	}
	subcommands[name] = subcommand{summary, run}
}

// Run dispatches to the subcommand named by args[0].
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(args) == 0 {
		printUsage(stderr)
		return errors.New("no subcommand given")
	}
	name := args[0]
	sc, ok := subcommands[name]
	if !ok {
		printUsage(stderr)
		return fmt.Errorf("unknown subcommand %q", name)
	}
	return sc.run(ctx, args[1:], stdout, stderr)
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: mesh-checker <subcommand> [flags]")
	fmt.Fprintln(w, "subcommands:")
	names := make([]string, 0, len(subcommands))
	for n := range subcommands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "  %-12s %s\n", n, subcommands[n].summary)
	}
}
