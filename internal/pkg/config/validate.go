package config

import (
	"encoding/base64"
	"fmt"
)

var validChecks = map[string]bool{"icmp": true, "tcp": true, "udp": true, "https": true}

// Validate returns the first hard error; warnings are silently dropped.
// Use ValidateWithWarnings to also collect non-fatal warnings.
func Validate(c *Config) error {
	_, err := ValidateWithWarnings(c)
	return err
}

// ValidateWithWarnings checks structural rules and returns
// (warnings, hardError). On hard error, warnings may be partial.
func ValidateWithWarnings(c *Config) ([]string, error) {
	if c.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("config: schemaVersion %d unsupported (want %d)", c.SchemaVersion, SchemaVersion)
	}
	if c.Host.Name == "" {
		return nil, fmt.Errorf("config: host.name is required")
	}
	if c.Probe.FailureThreshold > c.Probe.FailureWindow {
		return nil, fmt.Errorf("config: probe.failureThreshold (%d) must be <= failureWindow (%d)",
			c.Probe.FailureThreshold, c.Probe.FailureWindow)
	}
	if err := checkSecret("probe.udpSharedSecret", c.Probe.UDPSharedSecret); err != nil {
		return nil, err
	}
	if err := checkSecret("ui.sessionSecret", c.UI.SessionSecret); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var warnings []string
	for _, p := range c.Peers {
		if seen[p.Name] {
			return warnings, fmt.Errorf("config: duplicate peer name %q", p.Name)
		}
		seen[p.Name] = true
		for _, ch := range p.Checks {
			if !validChecks[ch] {
				warnings = append(warnings, fmt.Sprintf("peer %q: unknown check %q (ignored)", p.Name, ch))
			}
		}
	}
	return warnings, nil
}

func checkSecret(field, b64 string) error {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("config: %s is not valid base64: %w", field, err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("config: %s must decode to 32 bytes, got %d", field, len(raw))
	}
	return nil
}
