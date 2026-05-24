package udp

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

// Prober sends a single HMAC-authenticated UDP probe request and waits for the
// matching response. It implements probe.Prober.
type Prober struct {
	Secret   []byte
	HostName string
	Timeout  time.Duration
}

// New creates a Prober with the given shared secret, local host name, and
// per-probe deadline.
func New(secret []byte, hostName string, timeout time.Duration) *Prober {
	return &Prober{Secret: secret, HostName: hostName, Timeout: timeout}
}

// Probe sends a request to target and returns the result. The returned error is
// always nil; failures are reported via Result.OK == false and Result.Err.
func (p *Prober) Probe(ctx context.Context, target probe.Target) (probe.Result, error) {
	start := time.Now()
	r := probe.Result{Timestamp: start}

	nonce, err := NewNonce()
	if err != nil {
		r.Err = err.Error()
		return r, nil
	}
	req, err := EncodeRequest(p.Secret, nonce, start, p.HostName)
	if err != nil {
		r.Err = err.Error()
		return r, nil
	}
	addr := fmt.Sprintf("%s:%d", target.Addr, target.UDPPort)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		r.Err = err.Error()
		return r, nil
	}
	defer conn.Close()
	deadline := start.Add(p.Timeout)
	conn.SetDeadline(deadline)
	if _, err := conn.Write(req); err != nil {
		r.Err = err.Error()
		return r, nil
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	r.Latency = time.Since(start)
	if err != nil {
		r.Err = err.Error()
		return r, nil
	}
	gotNonce, _, err := DecodeResponse(p.Secret, buf[:n])
	if err != nil {
		r.Err = err.Error()
		return r, nil
	}
	if !bytes.Equal(gotNonce[:], nonce[:]) {
		r.Err = "nonce mismatch"
		return r, nil
	}
	r.OK = true
	return r, nil
}
