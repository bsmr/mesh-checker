// Package version exposes the build's semantic version, injected at
// build time via -ldflags so the binary and the repo-root VERSION file
// cannot drift.
//
// Build with:
//
//	go build -ldflags "-X github.com/bsmr/mesh-checker/internal/pkg/version.version=$(cat VERSION)" -o bin/mesh-checker ./cmd/mesh-checker
//
// When built without -ldflags (e.g. plain `go test`), String returns "dev".
package version

// version is overridden at build time by -ldflags -X.
var version = "dev"

// String returns the build-time version, e.g. "0.1.0", or "dev" for
// unstamped builds.
func String() string {
	return version
}
