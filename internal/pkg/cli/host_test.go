package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/bsmr/mesh-checker/internal/pkg/config"
)

func TestHostAddAppendsPeerToConfig(t *testing.T) {
	path := writeMinimalConfig(t)
	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(),
		[]string{"host", "add", "node-b", "10.0.0.2", "--config", path},
		&stdout, &stderr); err != nil {
		t.Fatalf("host add: %v (stderr=%q)", err, stderr.String())
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Peers) != 1 || cfg.Peers[0].Name != "node-b" {
		t.Errorf("peers = %v", cfg.Peers)
	}
}

func TestHostListPrintsPeers(t *testing.T) {
	path := writeMinimalConfig(t)
	var stdout, stderr bytes.Buffer
	_ = Run(context.Background(), []string{"host", "add", "node-b", "10.0.0.2", "--config", path}, &stdout, &stderr)
	stdout.Reset()
	if err := Run(context.Background(), []string{"host", "list", "--config", path}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "node-b") {
		t.Errorf("expected 'node-b' in output, got %q", stdout.String())
	}
}

func TestHostRemoveDropsPeer(t *testing.T) {
	path := writeMinimalConfig(t)
	var stdout, stderr bytes.Buffer
	_ = Run(context.Background(), []string{"host", "add", "node-b", "10.0.0.2", "--config", path}, &stdout, &stderr)
	_ = Run(context.Background(), []string{"host", "remove", "node-b", "--config", path}, &stdout, &stderr)
	cfg, _ := config.Load(path)
	if len(cfg.Peers) != 0 {
		t.Errorf("expected 0 peers, got %d", len(cfg.Peers))
	}
}
