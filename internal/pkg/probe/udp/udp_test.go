package udp

import (
	"context"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

func startEchoFake(t *testing.T, secret []byte) (port int, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1024)
		for {
			pc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				select {
				case <-done:
					return
				default:
					continue
				}
			}
			req, err := DecodeRequest(secret, buf[:n])
			if err != nil {
				continue
			}
			resp, _ := EncodeResponse(secret, req.Nonce, time.Now())
			pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port, func() { close(done); pc.Close() }
}

func TestUDPProberRoundTrip(t *testing.T) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	port, stop := startEchoFake(t, secret)
	defer stop()

	p := New(secret, "node-a", 500*time.Millisecond)
	res, err := p.Probe(context.Background(), probe.Target{Addr: "127.0.0.1", UDPPort: port})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Errorf("expected OK, got %+v", res)
	}
}

func TestUDPProberTimesOutWithoutResponder(t *testing.T) {
	secret := make([]byte, 32)
	p := New(secret, "node-a", 100*time.Millisecond)
	res, _ := p.Probe(context.Background(), probe.Target{Addr: "127.0.0.1", UDPPort: 1})
	if res.OK {
		t.Errorf("expected failure, got OK")
	}
}
