package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestConfigValidateAcceptsGoodConfig(t *testing.T) {
	path := writeMinimalConfig(t)
	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(),
		[]string{"config", "validate", "--config", path}, &stdout, &stderr); err != nil {
		t.Errorf("expected nil, got %v (stderr=%q)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "OK") {
		t.Errorf("expected OK in stdout, got %q", stdout.String())
	}
}

func TestConfigValidateRejectsBadSchema(t *testing.T) {
	path := writeMinimalConfig(t)
	// Overwrite with bogus content via writeStrict (defined in pki.go).
	if err := writeStrict(path, []byte(`{"schemaVersion":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{"config", "validate", "--config", path}, &stdout, &stderr)
	if err == nil {
		t.Error("expected error for bad schema, got nil")
	}
}
