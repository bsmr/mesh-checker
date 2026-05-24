// Package icmp implements probe.Prober via ICMP Echo. Requires
// cap_net_raw on the binary. Pure packet build/parse is unit-tested;
// live socket behaviour is covered by an integration test behind
// the //go:build integration tag.
package icmp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
	"github.com/bsmr/mesh-checker/internal/pkg/recoverwrap"
)

func buildEcho(id, seq int, payload []byte) ([]byte, error) {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: payload},
	}
	return msg.Marshal(nil)
}

func parseEchoReply(b []byte) (id, seq int, payload []byte, err error) {
	m, err := icmp.ParseMessage(int(ipv4.ICMPTypeEchoReply.Protocol()), b)
	if err != nil {
		// Also try parsing as echo request (used in unit tests where we
		// "round-trip" through Marshal+ParseMessage on the request side).
		m, err = icmp.ParseMessage(1, b)
		if err != nil {
			return 0, 0, nil, err
		}
	}
	e, ok := m.Body.(*icmp.Echo)
	if !ok {
		return 0, 0, nil, errors.New("icmp: not an echo body")
	}
	return e.ID, e.Seq, e.Data, nil
}

// Prober owns a raw socket and demultiplexes replies by sequence.
type Prober struct {
	id      int
	timeout time.Duration

	mu      sync.Mutex
	nextSeq int
	pending map[int]chan probe.Result
	conn    *icmp.PacketConn
}

// New opens a raw ICMP socket. Caller must hold cap_net_raw.
func New(timeout time.Duration) (*Prober, error) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("icmp: %w", err)
	}
	p := &Prober{
		id:      os.Getpid() & 0xffff,
		timeout: timeout,
		pending: map[int]chan probe.Result{},
		conn:    c,
	}
	recoverwrap.Go("icmp.readLoop", p.readLoop)
	return p, nil
}

// Close shuts down the ICMP socket.
func (p *Prober) Close() error { return p.conn.Close() }

func (p *Prober) readLoop() {
	buf := make([]byte, 1500)
	for {
		n, _, err := p.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		_, seq, _, err := parseEchoReply(buf[:n])
		if err != nil {
			continue
		}
		p.mu.Lock()
		ch, ok := p.pending[seq]
		delete(p.pending, seq)
		p.mu.Unlock()
		if ok {
			ch <- probe.Result{Timestamp: time.Now(), OK: true}
		}
	}
}

// Probe sends an ICMP Echo Request to target.Addr and waits for a reply.
func (p *Prober) Probe(ctx context.Context, target probe.Target) (probe.Result, error) {
	start := time.Now()
	p.mu.Lock()
	p.nextSeq = (p.nextSeq + 1) & 0xffff
	seq := p.nextSeq
	ch := make(chan probe.Result, 1)
	p.pending[seq] = ch
	p.mu.Unlock()

	pkt, err := buildEcho(p.id, seq, []byte("mesh-checker"))
	if err != nil {
		return probe.Result{Timestamp: start, Err: err.Error()}, nil
	}
	if _, err := p.conn.WriteTo(pkt, &net.IPAddr{IP: net.ParseIP(target.Addr)}); err != nil {
		return probe.Result{Timestamp: start, Err: err.Error()}, nil
	}
	select {
	case r := <-ch:
		r.Latency = time.Since(start)
		r.Timestamp = start
		return r, nil
	case <-time.After(p.timeout):
		p.mu.Lock()
		delete(p.pending, seq)
		p.mu.Unlock()
		return probe.Result{Timestamp: start, Latency: time.Since(start), Err: "timeout"}, nil
	case <-ctx.Done():
		return probe.Result{Timestamp: start, Err: ctx.Err().Error()}, nil
	}
}
