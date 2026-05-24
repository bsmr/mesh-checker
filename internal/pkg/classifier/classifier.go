// Package classifier maps a sliding window of probe.Result samples to
// a coarse state: Up, Degraded, Down, or Unknown (too few samples).
package classifier

import "github.com/bsmr/mesh-checker/internal/pkg/probe"

type State string

const (
	Unknown  State = "unknown"
	Up       State = "up"
	Degraded State = "degraded"
	Down     State = "down"
)

// Classify inspects the trailing `window` samples of results.
// - Unknown if fewer than `window` samples available.
// - Down if at least `threshold` of the last `window` failed.
// - Up if all `window` succeeded.
// - Degraded otherwise.
func Classify(results []probe.Result, window, threshold int) State {
	if len(results) < window {
		return Unknown
	}
	tail := results[len(results)-window:]
	fails := 0
	for _, r := range tail {
		if !r.OK {
			fails++
		}
	}
	switch {
	case fails >= threshold:
		return Down
	case fails == 0:
		return Up
	default:
		return Degraded
	}
}
