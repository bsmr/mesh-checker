package probe

import (
	"log/slog"
	"net"
	"sync"
	"time"

	udppayload "github.com/bsmr/mesh-checker/internal/pkg/probe/udp"
)

type UDPEcho struct {
	pc       net.PacketConn
	secret   []byte
	allowed  map[string]bool
	replay   *udppayload.ReplayCache
	mu       sync.Mutex
	closed   bool
	tsWindow time.Duration
}

func NewUDPEcho(listenAddr string, secret []byte, allowedIPs map[string]bool) (*UDPEcho, error) {
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	return &UDPEcho{
		pc: pc, secret: secret, allowed: allowedIPs,
		replay:   udppayload.NewReplayCache(60 * time.Second),
		tsWindow: 30 * time.Second,
	}, nil
}

func (s *UDPEcho) Addr() string { return s.pc.LocalAddr().String() }

func (s *UDPEcho) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return s.pc.Close()
}

func (s *UDPEcho) Run() {
	buf := make([]byte, 2048)
	for {
		n, addr, err := s.pc.ReadFrom(buf)
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			slog.Warn("udp echo read", "err", err)
			continue
		}
		s.handle(buf[:n], addr)
	}
}

func (s *UDPEcho) handle(pkt []byte, addr net.Addr) {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil || !s.allowed[host] {
		return
	}
	req, err := udppayload.DecodeRequest(s.secret, pkt)
	if err != nil {
		return
	}
	now := time.Now()
	if diff := now.Sub(req.Timestamp); diff > s.tsWindow || diff < -s.tsWindow {
		return
	}
	if s.replay.SeenOrAdd(req.Nonce, now) {
		return
	}
	resp, err := udppayload.EncodeResponse(s.secret, req.Nonce, now)
	if err != nil {
		return
	}
	_, _ = s.pc.WriteTo(resp, addr)
}
