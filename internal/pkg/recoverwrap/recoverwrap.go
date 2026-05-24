// Package recoverwrap provides Go(), a panic-recovering goroutine launcher.
// Every long-running goroutine in the daemon is launched via Go so a single
// panic cannot crash the process (mesh-checker design spec, section 11).
package recoverwrap

import (
	"log/slog"
	"runtime/debug"
)

// Go runs fn in a new goroutine. If fn panics, the panic is recovered
// and logged via slog at error level, scoped by name.
func Go(scope string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("goroutine panic recovered",
					"scope", scope,
					"panic", r,
					"stack", string(debug.Stack()))
			}
		}()
		fn()
	}()
}
