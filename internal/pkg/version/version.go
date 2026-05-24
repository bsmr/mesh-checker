// Package version exposes the build's semantic version, embedded from
// the repo-root VERSION file so the binary and the file cannot drift.
//
// The VERSION file in this directory is kept in sync with the repo-root
// VERSION via go generate. Run `go generate ./internal/pkg/version/` after
// updating the root VERSION file.
//
//go:generate cp ../../../VERSION VERSION
package version

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var versionFile string

// String returns the trimmed version, e.g. "0.1.0".
func String() string {
	return strings.TrimSpace(versionFile)
}
