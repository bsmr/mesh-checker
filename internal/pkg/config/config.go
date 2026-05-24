// Package config defines the on-disk JSON schema and provides atomic
// load/save plus permission validation (mode.go, validate.go come in
// later tasks).
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

const SchemaVersion = 1

type Config struct {
	SchemaVersion int           `json:"schemaVersion"`
	Host          HostInfo      `json:"host"`
	PKI           PKIPaths      `json:"pki"`
	Listeners     Listeners     `json:"listeners"`
	Probe         ProbeSettings `json:"probe"`
	Peers         []Peer        `json:"peers"`
	UI            UI            `json:"ui"`
	Log           Log           `json:"log"`
}

type HostInfo struct {
	Name          string `json:"name"`
	AdvertiseAddr string `json:"advertiseAddr"`
}

type PKIPaths struct {
	CACertPath   string `json:"caCertPath"`
	CAKeyPath    string `json:"caKeyPath"`
	HostCertPath string `json:"hostCertPath"`
	HostKeyPath  string `json:"hostKeyPath"`
}

type Listeners struct {
	InterHost ListenerAddr  `json:"interhost"`
	UI        ListenerAddr  `json:"ui"`
	Probe     ProbeListener `json:"probe"`
}

type ListenerAddr struct {
	Addr string `json:"addr"`
}

type ProbeListener struct {
	HTTPAddr string `json:"httpAddr"`
	UDPAddr  string `json:"udpAddr"`
}

type ProbeSettings struct {
	IntervalSeconds  int    `json:"intervalSeconds"`
	JitterPercent    int    `json:"jitterPercent"`
	TimeoutSeconds   int    `json:"timeoutSeconds"`
	FailureWindow    int    `json:"failureWindow"`
	FailureThreshold int    `json:"failureThreshold"`
	RingbufferSize   int    `json:"ringbufferSize"`
	UDPSharedSecret  string `json:"udpSharedSecret"`
}

type Peer struct {
	Name     string   `json:"name"`
	Addr     string   `json:"addr"`
	Checks   []string `json:"checks"`
	TCPPort  int      `json:"tcpPort,omitempty"`
	UDPPort  int      `json:"udpPort,omitempty"`
	HTTPSURL string   `json:"httpsURL,omitempty"`
}

type UI struct {
	Users             []User `json:"users"`
	SessionSecret     string `json:"sessionSecret"`
	SessionTTLSeconds int    `json:"sessionTTLSeconds"`
}

type User struct {
	Name         string `json:"name"`
	PasswordHash string `json:"passwordHash"`
}

type Log struct {
	Level string `json:"level"`
}

// Load reads and JSON-decodes a config file. Permission and structural
// checks are separate.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	c := &Config{}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("config: decode %s: %w", path, err)
	}
	return c, nil
}

// Save writes the config atomically: marshal -> temp file -> rename.
func Save(path string, c *Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("config: write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("config: rename: %w", err)
	}
	return nil
}
