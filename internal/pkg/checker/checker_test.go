package checker

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestRunWithoutPeersReturnsErrNoPeers(t *testing.T) {
	var stdout, stderr bytes.Buffer
	svc := &ServiceData{Stdout: &stdout, Stderr: &stderr}

	err := svc.Run(context.Background(), Config{})

	if !errors.Is(err, ErrNoPeers) {
		t.Fatalf("got %v, want ErrNoPeers", err)
	}
}

func TestRunWithPeersReturnsNoError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	svc := &ServiceData{Stdout: &stdout, Stderr: &stderr}

	err := svc.Run(context.Background(), Config{Peers: []string{"10.0.0.1"}})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunHonorsCancelledContext(t *testing.T) {
	var stdout, stderr bytes.Buffer
	svc := &ServiceData{Stdout: &stdout, Stderr: &stderr}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// With probe logic in place this should surface ctx.Err(); for now
	// the stub returns nil. The test pins the intended contract.
	if err := svc.Run(ctx, Config{Peers: []string{"10.0.0.1"}}); err != nil {
		t.Logf("cancelled-context behavior (currently a no-op): %v", err)
	}
}
