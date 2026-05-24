package scheduler

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
	"github.com/bsmr/mesh-checker/internal/pkg/store"
)

type countingProber struct{ n atomic.Int64 }

func (c *countingProber) Probe(ctx context.Context, t probe.Target) (probe.Result, error) {
	c.n.Add(1)
	return probe.Result{Timestamp: time.Now(), OK: true}, nil
}

func TestSchedulerRunsConfiguredJobs(t *testing.T) {
	st := store.New(10)
	cp := &countingProber{}
	jobs := []Job{
		{Peer: "node-b", Protocol: probe.TCP, Target: probe.Target{Name: "node-b"}, Prober: cp},
	}
	cfg := Config{Interval: 30 * time.Millisecond, JitterPercent: 0, Workers: 2}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	s := New(cfg, jobs, st)
	s.Run(ctx)

	if got := cp.n.Load(); got < 3 {
		t.Errorf("expected >=3 probes in 120ms, got %d", got)
	}
	if snap := st.Snapshot("node-b", probe.TCP); len(snap) < 3 {
		t.Errorf("store has %d samples, want >=3", len(snap))
	}
}

func TestSchedulerStopsOnContextCancel(t *testing.T) {
	st := store.New(10)
	cp := &countingProber{}
	jobs := []Job{{Peer: "p", Protocol: probe.TCP, Prober: cp}}
	cfg := Config{Interval: 20 * time.Millisecond, JitterPercent: 0, Workers: 1}
	ctx, cancel := context.WithCancel(context.Background())
	s := New(cfg, jobs, st)
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("scheduler did not stop after cancel")
	}
}
