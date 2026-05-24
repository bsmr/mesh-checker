// Package probe (server) implements the probe-target listeners:
// an HTTP /probe handler (anyone can hit it) and a UDP echo server
// that authenticates requests via HMAC and a peer-IP allowlist.
package probe

import (
	"fmt"
	"net/http"

	"github.com/bsmr/mesh-checker/internal/pkg/version"
)

// NewHTTPHandler returns a handler that responds 200 to GET /probe
// and 404 to everything else. No state, no auth.
func NewHTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "mesh-checker %s\n", version.String())
	})
	return mux
}
