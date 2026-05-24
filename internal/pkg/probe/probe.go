// Package probe defines the Prober interface and shared types used by
// the scheduler and every protocol-specific implementation.
package probe

import (
	"context"
	"time"
)

// Protocol identifies one of the four checks.
type Protocol string

const (
	ICMP  Protocol = "icmp"
	TCP   Protocol = "tcp"
	UDP   Protocol = "udp"
	HTTPS Protocol = "https"
)

// Target describes one peer that a Prober will probe.
type Target struct {
	Name     string
	Addr     string
	TCPPort  int
	UDPPort  int
	HTTPSURL string
}

// Result is one sample, success or failure.
type Result struct {
	Timestamp time.Time
	Latency   time.Duration
	OK        bool
	Err       string
}

// Prober probes one target. Implementations live in subpackages
// (tcp, http, udp, icmp).
type Prober interface {
	Probe(ctx context.Context, target Target) (Result, error)
}
