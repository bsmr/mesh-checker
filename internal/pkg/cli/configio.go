package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/bsmr/mesh-checker/internal/pkg/config"
)

const defaultConfigPath = "/etc/mesh-checker/config.json"

// addConfigFlag registers --config on fs and returns the bound pointer.
func addConfigFlag(fs *flag.FlagSet) *string {
	return fs.String("config", defaultConfigPath, "path to config.json")
}

// loadAndMutate is the canonical edit-config workflow: Load, run fn, Save.
// File permission check (CheckMode) is skipped here because mutating
// subcommands also run on freshly-created config files during bootstrap.
func loadAndMutate(path string, fn func(*config.Config) error) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if err := fn(cfg); err != nil {
		return err
	}
	return config.Save(path, cfg)
}

// newConfigSkeleton builds a minimal but valid config wired to the given
// PKI paths and ephemeral ports — used by serve_test.go and any other
// CLI test that needs a runnable config.
func newConfigSkeleton(hostName, addr, caCert, hostCert, hostKey string, ihPort, uiPort, probeHTTP, probeUDP int) *config.Config {
	const sec = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	return &config.Config{
		SchemaVersion: 1,
		Host:          config.HostInfo{Name: hostName, AdvertiseAddr: addr},
		PKI:           config.PKIPaths{CACertPath: caCert, CAKeyPath: "", HostCertPath: hostCert, HostKeyPath: hostKey},
		Listeners: config.Listeners{
			InterHost: config.ListenerAddr{Addr: fmt.Sprintf("127.0.0.1:%d", ihPort)},
			UI:        config.ListenerAddr{Addr: fmt.Sprintf("127.0.0.1:%d", uiPort)},
			Probe:     config.ProbeListener{HTTPAddr: fmt.Sprintf("127.0.0.1:%d", probeHTTP), UDPAddr: fmt.Sprintf("127.0.0.1:%d", probeUDP)},
		},
		Probe: config.ProbeSettings{
			IntervalSeconds: 10, JitterPercent: 10, TimeoutSeconds: 3,
			FailureWindow: 5, FailureThreshold: 3, RingbufferSize: 100,
			UDPSharedSecret: sec,
		},
		UI:  config.UI{SessionSecret: sec, SessionTTLSeconds: 3600},
		Log: config.Log{Level: "info"},
	}
}

func saveStrict(path string, c *config.Config) error {
	if err := config.Save(path, c); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
