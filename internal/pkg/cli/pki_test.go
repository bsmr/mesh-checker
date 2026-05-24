package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPKIInitWritesCAFilesWithStrictMode(t *testing.T) {
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(),
		[]string{"pki", "init", "--ca-cert", caCert, "--ca-key", caKey},
		&stdout, &stderr)
	if err != nil {
		t.Fatalf("pki init failed: %v (stderr=%q)", err, stderr.String())
	}
	st, err := os.Stat(caKey)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("ca.key mode = %o, want 0600", st.Mode().Perm())
	}
}

func TestPKICertWritesHostMaterial(t *testing.T) {
	dir := t.TempDir()
	caCert := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	hostCert := filepath.Join(dir, "node-a.crt")
	hostKey := filepath.Join(dir, "node-a.key")

	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(),
		[]string{"pki", "init", "--ca-cert", caCert, "--ca-key", caKey},
		&stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(),
		[]string{"pki", "cert", "node-a",
			"--ca-cert", caCert, "--ca-key", caKey,
			"--out-cert", hostCert, "--out-key", hostKey,
			"--san", "10.0.0.1"},
		&stdout, &stderr); err != nil {
		t.Fatalf("pki cert failed: %v (stderr=%q)", err, stderr.String())
	}
	if _, err := os.Stat(hostCert); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(hostKey); st.Mode().Perm() != 0o600 {
		t.Errorf("host key mode = %o", st.Mode().Perm())
	}
}
