// Package checker probes reachability of mesh peers across ICMP, TCP, and UDP.
//
// This is the service layer invoked by the CLI in cmd/mesh-checker. It is
// intentionally I/O-injected (stdout/stderr as io.Writer) and context-driven
// so callers control cancellation and output destinations.
package checker

import (
	"context"
	"errors"
	"io"
)

// Config holds the inputs for a single checker run. Fields will grow as
// peer-list parsing, protocol selection, timeouts, etc. are implemented.
type Config struct {
	// Peers is the list of target addresses to probe. Empty means no work.
	Peers []string
}

// ServiceData is the stateful handle for a checker invocation. Stdout and
// Stderr are injected by the caller so tests can capture output.
type ServiceData struct {
	Stdout io.Writer
	Stderr io.Writer
}

// ErrNoPeers is returned when Run is invoked with an empty peer list. The
// CLI surfaces this as a usage error rather than a silent no-op.
var ErrNoPeers = errors.New("no peers configured")

// Run executes the configured probes. It honors ctx for cancellation and
// returns the first fatal error; per-peer probe failures are reported via
// Stdout/Stderr and do not abort the run.
func (s *ServiceData) Run(ctx context.Context, cfg Config) error {
	if len(cfg.Peers) == 0 {
		return ErrNoPeers
	}
	// TODO: dispatch ICMP/TCP/UDP probes per peer.
	return nil
}
