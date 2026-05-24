// Package store keeps a fixed-capacity ringbuffer of probe.Result
// per (peer, protocol) key. Thread-safe.
package store

import (
	"sync"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

// Key uniquely identifies a (peer, protocol) pair.
type Key struct {
	Peer     string
	Protocol probe.Protocol
}

// Store holds a ringbuffer per Key, all guarded by a single RWMutex.
type Store struct {
	cap  int
	mu   sync.RWMutex
	bufs map[Key]*ring
}

// New returns a Store with per-key ringbuffers of the given capacity.
// If capacity < 1 it is raised to 1.
func New(capacity int) *Store {
	if capacity < 1 {
		capacity = 1
	}
	return &Store{cap: capacity, bufs: map[Key]*ring{}}
}

// Append adds r to the ringbuffer for (peer, p), allocating one on first use.
func (s *Store) Append(peer string, p probe.Protocol, r probe.Result) {
	k := Key{peer, p}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.bufs[k]
	if !ok {
		b = newRing(s.cap)
		s.bufs[k] = b
	}
	b.push(r)
}

// Snapshot returns a copy of all buffered results for (peer, p) in
// insertion order (oldest first). Returns nil when the key is unknown.
func (s *Store) Snapshot(peer string, p probe.Protocol) []probe.Result {
	k := Key{peer, p}
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.bufs[k]
	if !ok {
		return nil
	}
	return b.snapshot()
}

// Keys returns a snapshot of all (peer, protocol) keys currently stored.
func (s *Store) Keys() []Key {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Key, 0, len(s.bufs))
	for k := range s.bufs {
		out = append(out, k)
	}
	return out
}

// ring is a fixed-capacity circular buffer of probe.Result values.
type ring struct {
	buf  []probe.Result
	head int // next write position
	full bool
}

func newRing(n int) *ring { return &ring{buf: make([]probe.Result, n)} }

func (r *ring) push(v probe.Result) {
	r.buf[r.head] = v
	r.head = (r.head + 1) % len(r.buf)
	if r.head == 0 {
		r.full = true
	}
}

func (r *ring) snapshot() []probe.Result {
	if !r.full {
		out := make([]probe.Result, r.head)
		copy(out, r.buf[:r.head])
		return out
	}
	out := make([]probe.Result, len(r.buf))
	copy(out, r.buf[r.head:])
	copy(out[len(r.buf)-r.head:], r.buf[:r.head])
	return out
}
