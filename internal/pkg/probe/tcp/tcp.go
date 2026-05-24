// Package tcp implements probe.Prober via TCP connect + immediate close.
package tcp

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

type Prober struct {
	Timeout time.Duration
}

func New(timeout time.Duration) *Prober { return &Prober{Timeout: timeout} }

func (p *Prober) Probe(ctx context.Context, target probe.Target) (probe.Result, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()
	d := net.Dialer{}
	addr := net.JoinHostPort(target.Addr, strconv.Itoa(target.TCPPort))
	conn, err := d.DialContext(ctx, "tcp", addr)
	r := probe.Result{Timestamp: start, Latency: time.Since(start)}
	if err != nil {
		r.Err = err.Error()
		return r, nil
	}
	conn.Close()
	r.OK = true
	return r, nil
}
