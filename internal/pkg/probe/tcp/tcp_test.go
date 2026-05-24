package tcp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

func TestProbeReturnsOKWhenListenerAccepts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	p := New(500 * time.Millisecond)
	res, err := p.Probe(context.Background(), probe.Target{Addr: "127.0.0.1", TCPPort: port})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Errorf("expected OK, got %+v", res)
	}
}

func TestProbeReturnsFailWhenPortClosed(t *testing.T) {
	p := New(100 * time.Millisecond)
	res, _ := p.Probe(context.Background(), probe.Target{Addr: "127.0.0.1", TCPPort: 1})
	if res.OK {
		t.Errorf("expected failure, got OK")
	}
	if res.Err == "" {
		t.Error("expected non-empty Err")
	}
}
