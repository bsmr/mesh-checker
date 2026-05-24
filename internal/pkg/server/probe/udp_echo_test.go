package probe

import (
	"crypto/rand"
	"net"
	"testing"
	"time"

	udppayload "github.com/bsmr/mesh-checker/internal/pkg/probe/udp"
)

func TestUDPEchoServerEchoesAuthorisedPeer(t *testing.T) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	allowed := map[string]bool{"127.0.0.1": true}

	s, err := NewUDPEcho("127.0.0.1:0", secret, allowed)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Run()

	nonce, _ := udppayload.NewNonce()
	req, _ := udppayload.EncodeRequest(secret, nonce, time.Now(), "node-a")

	conn, err := net.Dial("udp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n >= len(req) {
		t.Errorf("response (%d) must be < request (%d)", n, len(req))
	}
}

func TestUDPEchoRejectsBadHMAC(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)
	s, _ := NewUDPEcho("127.0.0.1:0", secret, map[string]bool{"127.0.0.1": true})
	defer s.Close()
	go s.Run()

	nonce, _ := udppayload.NewNonce()
	req, _ := udppayload.EncodeRequest(secret, nonce, time.Now(), "node-a")
	req[len(req)-1] ^= 0xff
	conn, _ := net.Dial("udp", s.Addr())
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
	conn.Write(req)
	buf := make([]byte, 1024)
	if _, err := conn.Read(buf); err == nil {
		t.Error("expected no response on bad HMAC")
	}
}

func TestUDPEchoRejectsSourceNotInAllowlist(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)
	// Empty allowlist: 127.0.0.1 will not match.
	s, err := NewUDPEcho("127.0.0.1:0", secret, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	go s.Run()

	nonce, _ := udppayload.NewNonce()
	req, _ := udppayload.EncodeRequest(secret, nonce, time.Now(), "node-a")

	conn, _ := net.Dial("udp", s.Addr())
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
	conn.Write(req)
	buf := make([]byte, 1024)
	if _, err := conn.Read(buf); err == nil {
		t.Error("expected no response from non-allowlisted source")
	}
}

func TestUDPEchoRejectsStaleTimestamp(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)
	s, _ := NewUDPEcho("127.0.0.1:0", secret, map[string]bool{"127.0.0.1": true})
	defer s.Close()
	go s.Run()

	nonce, _ := udppayload.NewNonce()
	// Timestamp 60s in the past: outside the 30s window.
	req, _ := udppayload.EncodeRequest(secret, nonce, time.Now().Add(-60*time.Second), "node-a")
	conn, _ := net.Dial("udp", s.Addr())
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
	conn.Write(req)
	buf := make([]byte, 1024)
	if _, err := conn.Read(buf); err == nil {
		t.Error("expected no response for stale timestamp")
	}
}

func TestUDPEchoRejectsReplayedNonce(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)
	s, _ := NewUDPEcho("127.0.0.1:0", secret, map[string]bool{"127.0.0.1": true})
	defer s.Close()
	go s.Run()

	nonce, _ := udppayload.NewNonce()
	req, _ := udppayload.EncodeRequest(secret, nonce, time.Now(), "node-a")

	conn, _ := net.Dial("udp", s.Addr())
	defer conn.Close()

	// First send: must succeed.
	conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("first send: expected response, got error: %v", err)
	}

	// Second send with identical nonce: must NOT get a response.
	conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(buf); err == nil {
		t.Error("expected no response for replayed nonce")
	}
}
