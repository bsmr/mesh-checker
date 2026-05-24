package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bsmr/mesh-checker/internal/pkg/config"
)

// writeMinimalConfig writes a permission-correct config with one host but
// no peers. Shared test helper for cli tests.
func writeMinimalConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	cfg := &config.Config{
		SchemaVersion: 1,
		Host:          config.HostInfo{Name: "node-a", AdvertiseAddr: "10.0.0.1"},
		PKI:           config.PKIPaths{CACertPath: "x", CAKeyPath: "y", HostCertPath: "z", HostKeyPath: "k"},
		Listeners: config.Listeners{
			InterHost: config.ListenerAddr{Addr: "0.0.0.0:8443"},
			UI:        config.ListenerAddr{Addr: "0.0.0.0:8080"},
			Probe:     config.ProbeListener{HTTPAddr: "0.0.0.0:7080", UDPAddr: "0.0.0.0:7081"},
		},
		Probe: config.ProbeSettings{
			IntervalSeconds: 10, JitterPercent: 10, TimeoutSeconds: 3,
			FailureWindow: 5, FailureThreshold: 3, RingbufferSize: 100,
			UDPSharedSecret: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		},
		UI: config.UI{
			SessionSecret:     "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
			SessionTTLSeconds: 3600,
		},
		Log: config.Log{Level: "info"},
	}
	if err := config.Save(p, cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
