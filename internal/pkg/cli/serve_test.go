package cli

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// TestServeStartsAndStopsCleanly writes a working config and PKI tree,
// runs `serve` for ~150ms, cancels, and asserts no error returned.
func TestServeStartsAndStopsCleanly(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	if err := Run(context.Background(),
		[]string{"pki", "init", "--ca-cert", caCert, "--ca-key", caKey},
		&stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	hostCert := filepath.Join(dir, "node-a.crt")
	hostKey := filepath.Join(dir, "node-a.key")
	if err := Run(context.Background(),
		[]string{"pki", "cert", "node-a",
			"--ca-cert", caCert, "--ca-key", caKey,
			"--out-cert", hostCert, "--out-key", hostKey,
			"--san", "127.0.0.1"},
		&stdout, &stderr); err != nil {
		t.Fatal(err)
	}

	cfgPath := writeServeConfig(t, dir, caCert, hostCert, hostKey)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	err := Run(ctx, []string{"serve", "--config", cfgPath}, &stdout, &stderr)
	if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
		t.Fatalf("serve returned unexpected error: %v (stderr=%q)", err, stderr.String())
	}
}

// writeServeConfig builds a config that binds to ephemeral ports.
func writeServeConfig(t *testing.T, dir, caCert, hostCert, hostKey string) string {
	t.Helper()
	freePort := func() int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		return ln.Addr().(*net.TCPAddr).Port
	}
	freeUDP := func() int {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		return pc.LocalAddr().(*net.UDPAddr).Port
	}
	cfg := newConfigSkeleton("node-a", "127.0.0.1", caCert, hostCert, hostKey, freePort(), freePort(), freePort(), freeUDP())
	p := filepath.Join(dir, "config.json")
	if err := saveStrict(p, cfg); err != nil {
		t.Fatal(err)
	}
	return p
}
