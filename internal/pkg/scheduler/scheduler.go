// Package scheduler drives Probers on a periodic schedule and writes
// their Results into the store. Each Job runs every Interval (+- jitter)
// dispatched on a bounded worker pool.
package scheduler

import (
	"context"
	"math/rand"
	"sync"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
	"github.com/bsmr/mesh-checker/internal/pkg/store"
)

// Job represents a single probe task to be scheduled.
type Job struct {
	Peer     string
	Protocol probe.Protocol
	Target   probe.Target
	Prober   probe.Prober
}

// Config holds scheduler configuration.
type Config struct {
	Interval      time.Duration
	JitterPercent int // 0..100
	Workers       int
	Timeout       time.Duration
}

// Scheduler drives Probers on a periodic schedule using a bounded worker pool.
type Scheduler struct {
	cfg   Config
	jobs  []Job
	store *store.Store
}

// New creates a new Scheduler. Workers defaults to 1 if set below 1.
func New(cfg Config, jobs []Job, st *store.Store) *Scheduler {
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	return &Scheduler{cfg: cfg, jobs: jobs, store: st}
}

// Run blocks until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	jobs := make(chan Job, len(s.jobs))
	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(ctx, jobs)
		}()
	}
	var tickerWG sync.WaitGroup
	for _, j := range s.jobs {
		j := j
		tickerWG.Add(1)
		go func() {
			defer tickerWG.Done()
			s.tickerLoop(ctx, j, jobs)
		}()
	}
	tickerWG.Wait()
	close(jobs)
	wg.Wait()
}

func (s *Scheduler) tickerLoop(ctx context.Context, j Job, out chan<- Job) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.next()):
			select {
			case out <- j:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (s *Scheduler) next() time.Duration {
	base := s.cfg.Interval
	if s.cfg.JitterPercent <= 0 {
		return base
	}
	delta := int64(base) * int64(s.cfg.JitterPercent) / 100
	if delta == 0 {
		return base
	}
	jit := rand.Int63n(2*delta+1) - delta
	return base + time.Duration(jit)
}

func (s *Scheduler) worker(ctx context.Context, in <-chan Job) {
	for j := range in {
		probeCtx := ctx
		if s.cfg.Timeout > 0 {
			var cancel context.CancelFunc
			probeCtx, cancel = context.WithTimeout(ctx, s.cfg.Timeout)
			r, _ := j.Prober.Probe(probeCtx, j.Target)
			cancel()
			s.store.Append(j.Peer, j.Protocol, r)
		} else {
			r, _ := j.Prober.Probe(probeCtx, j.Target)
			s.store.Append(j.Peer, j.Protocol, r)
		}
	}
}
