package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestRunWithoutSubcommandPrintsUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), nil, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error when no subcommand given")
	}
	if !strings.Contains(stderr.String(), "subcommand") {
		t.Errorf("expected usage to mention 'subcommand', got %q", stderr.String())
	}
}

func TestRunUnknownSubcommandReturnsError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{"frobnicate"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
	if !strings.Contains(err.Error(), "frobnicate") {
		t.Errorf("error should name the unknown subcommand, got %v", err)
	}
}

// registerForTest registers a subcommand for the duration of a test.
// Tests run sequentially in this package, so map mutation is safe.
func registerForTest(t *testing.T, name, summary string, run Handler) {
	t.Helper()
	register(name, summary, run)
	t.Cleanup(func() { delete(subcommands, name) })
}

func TestRunDispatchesToRegisteredSubcommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false
	registerForTest(t, "ping", "test stub", func(ctx context.Context, args []string, stdout, stderr io.Writer) error {
		called = true
		if len(args) != 2 || args[0] != "-n" || args[1] != "3" {
			t.Errorf("subcommand got wrong args: %v", args)
		}
		return nil
	})

	if err := Run(context.Background(), []string{"ping", "-n", "3"}, &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("subcommand handler was not invoked")
	}
}
