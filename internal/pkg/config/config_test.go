package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	in := &Config{
		SchemaVersion: 1,
		Host:          HostInfo{Name: "node-a", AdvertiseAddr: "10.0.0.1"},
		PKI: PKIPaths{
			CACertPath:   "/etc/mesh-checker/pki/ca.crt",
			CAKeyPath:    "/etc/mesh-checker/pki/ca.key",
			HostCertPath: "/etc/mesh-checker/pki/node-a.crt",
			HostKeyPath:  "/etc/mesh-checker/pki/node-a.key",
		},
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
		Peers: []Peer{{Name: "node-b", Addr: "10.0.0.2", Checks: []string{"icmp", "tcp", "udp", "https"}, TCPPort: 8443, UDPPort: 7081, HTTPSURL: "https://10.0.0.2:8080/probe"}},
		UI: UI{
			Users:             []User{{Name: "admin", PasswordHash: "$2b$12$abcdefghijklmnopqrstuv"}},
			SessionSecret:     "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
			SessionTTLSeconds: 28800,
		},
		Log: Log{Level: "info"},
	}

	if err := Save(path, in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round-trip mismatch:\nin:  %+v\nout: %+v", in, out)
	}
}

func TestSaveIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("OLD"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{SchemaVersion: 1, Host: HostInfo{Name: "x"}}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file not cleaned up: err=%v", err)
	}
}

func TestLoadMissingFileReturnsError(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Fatal("expected error loading missing file")
	}
}
