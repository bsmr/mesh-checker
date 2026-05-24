package store

import (
	"sync"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

func TestAppendAndSnapshotReturnsInOrder(t *testing.T) {
	s := New(3)
	s.Append("node-b", probe.TCP, probe.Result{Timestamp: time.Unix(1, 0), OK: true})
	s.Append("node-b", probe.TCP, probe.Result{Timestamp: time.Unix(2, 0), OK: false})
	snap := s.Snapshot("node-b", probe.TCP)
	if len(snap) != 2 {
		t.Fatalf("len = %d", len(snap))
	}
	if !snap[0].OK || snap[1].OK {
		t.Errorf("ordering wrong: %+v", snap)
	}
}

func TestRingbufferEvictsOldest(t *testing.T) {
	s := New(2)
	for i := 1; i <= 5; i++ {
		s.Append("p", probe.TCP, probe.Result{Timestamp: time.Unix(int64(i), 0), OK: true})
	}
	snap := s.Snapshot("p", probe.TCP)
	if len(snap) != 2 {
		t.Fatalf("len = %d", len(snap))
	}
	if snap[0].Timestamp.Unix() != 4 || snap[1].Timestamp.Unix() != 5 {
		t.Errorf("expected ts 4,5 got %d,%d", snap[0].Timestamp.Unix(), snap[1].Timestamp.Unix())
	}
}

func TestAllKeysListed(t *testing.T) {
	s := New(2)
	s.Append("a", probe.TCP, probe.Result{OK: true})
	s.Append("a", probe.UDP, probe.Result{OK: true})
	s.Append("b", probe.HTTPS, probe.Result{OK: true})
	keys := s.Keys()
	if len(keys) != 3 {
		t.Errorf("keys = %v", keys)
	}
}

func TestConcurrentAppendsSafe(t *testing.T) {
	s := New(100)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Append("p", probe.TCP, probe.Result{OK: true})
		}()
	}
	wg.Wait()
	if got := len(s.Snapshot("p", probe.TCP)); got != 50 {
		t.Errorf("expected 50, got %d", got)
	}
}
