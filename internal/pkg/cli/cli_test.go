package cli

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/bsmr/mesh-checker/internal/pkg/checker"
)

func TestRunWithoutPeersReturnsErrNoPeers(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := Run(context.Background(), nil, &stdout, &stderr)

	if !errors.Is(err, checker.ErrNoPeers) {
		t.Fatalf("got %v, want ErrNoPeers", err)
	}
	if !strings.Contains(stderr.String(), "peers") {
		t.Errorf("expected usage hint mentioning -peers on stderr, got: %q", stderr.String())
	}
}

func TestRunParsesCommaSeparatedPeers(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := Run(context.Background(), []string{"-peers", "10.0.0.1, 10.0.0.2 ,10.0.0.3"}, &stdout, &stderr)

	if err != nil {
		t.Fatalf("unexpected error: %v (stderr=%q)", err, stderr.String())
	}
}

func TestRunReturnsErrorOnUnknownFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := Run(context.Background(), []string{"-nonexistent"}, &stdout, &stderr)

	if err == nil {
		t.Fatal("expected error for unknown flag, got nil")
	}
}

func TestSplitPeersTrimsAndFiltersEmpty(t *testing.T) {
	cases := map[string][]string{
		"":                   nil,
		"a":                  {"a"},
		"a,b,c":              {"a", "b", "c"},
		" a , b , c ":        {"a", "b", "c"},
		"a,,b":               {"a", "b"},
		",,":                 nil,
		"10.0.0.1,10.0.0.2 ": {"10.0.0.1", "10.0.0.2"},
	}
	for in, want := range cases {
		got := splitPeers(in)
		if !slices.Equal(got, want) {
			t.Errorf("splitPeers(%q) = %v, want %v", in, got, want)
		}
	}
}
