// Package http implements an HTTPS prober that verifies peer certs
// against the mesh CA pool and looks for "mesh-checker" in the body.
package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

const bodyMarker = "mesh-checker"

type Prober struct {
	client *http.Client
}

func New(meshCA *x509.CertPool, timeout time.Duration) *Prober {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: meshCA, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}
	return &Prober{client: &http.Client{Transport: tr, Timeout: timeout}}
}

func (p *Prober) Probe(ctx context.Context, target probe.Target) (probe.Result, error) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, "GET", target.HTTPSURL, nil)
	if err != nil {
		return probe.Result{Timestamp: start, Err: err.Error()}, nil
	}
	resp, err := p.client.Do(req)
	r := probe.Result{Timestamp: start, Latency: time.Since(start)}
	if err != nil {
		r.Err = err.Error()
		return r, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		r.Err = fmt.Sprintf("status %d", resp.StatusCode)
		return r, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if !strings.Contains(string(body), bodyMarker) {
		r.Err = "body marker missing"
		return r, nil
	}
	r.OK = true
	return r, nil
}
