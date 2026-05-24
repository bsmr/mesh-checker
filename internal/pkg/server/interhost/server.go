// Package interhost is the mTLS inter-host API: read-only status and
// version endpoints, plus a peer client that other nodes' aggregators use.
package interhost

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bsmr/mesh-checker/internal/pkg/aggregator"
	"github.com/bsmr/mesh-checker/internal/pkg/version"
)

// Deps holds all dependencies required by the inter-host server.
type Deps struct {
	MeshCA     *x509.CertPool
	HostCert   tls.Certificate
	Peers      map[string]bool
	FetchLocal func() aggregator.ObserverView
}

// NewMux returns the inter-host HTTP routes. The TLS layer is set up
// by the caller using ServerTLSConfig.
func NewMux(d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/peer/status", peerCNCheck(d.Peers, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(d.FetchLocal())
	})))
	mux.Handle("/api/peer/version", peerCNCheck(d.Peers, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"version":%q,"schemaVersion":1}`, version.String())
	})))
	return mux
}

func peerCNCheck(peers map[string]bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "mTLS required", http.StatusForbidden)
			return
		}
		cn := r.TLS.VerifiedChains[0][0].Subject.CommonName
		if !peers[cn] {
			http.Error(w, "unknown peer", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ServerTLSConfig returns the *tls.Config to install on the inter-host
// listener.
func ServerTLSConfig(cert tls.Certificate, ca *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    ca,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
}
