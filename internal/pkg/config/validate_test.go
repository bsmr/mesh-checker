package config

import (
	"strings"
	"testing"
)

func validCfg() *Config {
	return &Config{
		SchemaVersion: 1,
		Host:          HostInfo{Name: "node-a", AdvertiseAddr: "10.0.0.1"},
		PKI:           PKIPaths{CACertPath: "x", CAKeyPath: "y", HostCertPath: "z", HostKeyPath: "k"},
		Listeners: Listeners{
			InterHost: ListenerAddr{Addr: "0.0.0.0:8443"},
			UI:        ListenerAddr{Addr: "0.0.0.0:8080"},
			Probe:     ProbeListener{HTTPAddr: "0.0.0.0:7080", UDPAddr: "0.0.0.0:7081"},
		},
		Probe: ProbeSettings{
			IntervalSeconds: 10, JitterPercent: 10, TimeoutSeconds: 3,
			FailureWindow: 5, FailureThreshold: 3, RingbufferSize: 100,
			UDPSharedSecret: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		},
		Peers: []Peer{{Name: "node-b", Addr: "10.0.0.2", Checks: []string{"tcp"}}},
		UI: UI{
			Users:             []User{{Name: "admin", PasswordHash: "$2b$12$x"}},
			SessionSecret:     "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
			SessionTTLSeconds: 3600,
		},
		Log: Log{Level: "info"},
	}
}

func TestValidateAcceptsGoodConfig(t *testing.T) {
	if err := Validate(validCfg()); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestValidateRejectsWrongSchemaVersion(t *testing.T) {
	c := validCfg()
	c.SchemaVersion = 2
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "schemaVersion") {
		t.Errorf("want schemaVersion error, got %v", err)
	}
}

func TestValidateRejectsDuplicatePeerNames(t *testing.T) {
	c := validCfg()
	c.Peers = append(c.Peers, Peer{Name: "node-b", Addr: "10.0.0.3", Checks: []string{"tcp"}})
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("want duplicate error, got %v", err)
	}
}

func TestValidateRejectsBadSecretLength(t *testing.T) {
	c := validCfg()
	c.Probe.UDPSharedSecret = "AAA="
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "udpSharedSecret") {
		t.Errorf("want udpSharedSecret error, got %v", err)
	}
}

func TestValidateRejectsThresholdGreaterThanWindow(t *testing.T) {
	c := validCfg()
	c.Probe.FailureThreshold = 99
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "failureThreshold") {
		t.Errorf("want threshold error, got %v", err)
	}
}

func TestValidateWarnsOnUnknownCheck(t *testing.T) {
	c := validCfg()
	c.Peers[0].Checks = []string{"tcp", "smtp"}
	warnings, err := ValidateWithWarnings(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "smtp") {
		t.Errorf("expected warning about 'smtp', got %v", warnings)
	}
}
