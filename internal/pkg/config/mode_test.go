package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckModeAcceptsTight(t *testing.T) {
	p := writeFile(t, 0o600)
	if err := CheckMode(p); err != nil {
		t.Errorf("0600 should be accepted, got %v", err)
	}
}

func TestCheckModeRejectsLoose(t *testing.T) {
	for _, m := range []os.FileMode{0o644, 0o640, 0o660, 0o666} {
		p := writeFile(t, m)
		if err := CheckMode(p); err == nil {
			t.Errorf("mode %o should be rejected", m)
		}
	}
}

func writeFile(t *testing.T, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("x"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}
