//go:build integration

package icmp

import (
	"context"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

func TestICMPProbesLoopback(t *testing.T) {
	p, err := New(2 * time.Second)
	if err != nil {
		t.Skipf("ICMP socket unavailable (cap_net_raw missing?): %v", err)
	}
	defer p.Close()
	res, err := p.Probe(context.Background(), probe.Target{Addr: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Errorf("loopback ICMP failed: %+v", res)
	}
}
