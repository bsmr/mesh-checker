// Package aggregator builds the merged mesh view shown in the UI by
// combining the local store with peers' /api/peer/status pulls.
package aggregator

import (
	"context"
	"sync"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/classifier"
	"github.com/bsmr/mesh-checker/internal/pkg/probe"
	"github.com/bsmr/mesh-checker/internal/pkg/store"
)

// Sample is one classified probe entry shown in the matrix.
type Sample struct {
	State  classifier.State `json:"state"`
	LastTS time.Time        `json:"lastTs,omitempty"`
}

// ObserverView is one host's view of every other host.
type ObserverView struct {
	Host      string                               `json:"host"`
	Samples   map[string]map[probe.Protocol]Sample `json:"samples"`
	Reachable bool                                 `json:"reachable"`
	Reason    string                               `json:"reason,omitempty"`
}

// MeshView is the merged response sent over SSE.
type MeshView struct {
	GeneratedAt time.Time               `json:"generatedAt"`
	Observers   map[string]ObserverView `json:"observers"`
}

// PeerClient fetches a peer's ObserverView over mTLS.
type PeerClient interface {
	Fetch(ctx context.Context, peer string) (ObserverView, error)
}

// Aggregator combines the local store with fan-out fetches from each peer.
type Aggregator struct {
	client    PeerClient
	store     *store.Store
	localHost string
	peers     []string
	window    int
	threshold int
	timeout   time.Duration
}

// New constructs an Aggregator.
func New(c PeerClient, st *store.Store, localHost string, peers []string, window, threshold int, peerTimeout time.Duration) *Aggregator {
	return &Aggregator{c, st, localHost, peers, window, threshold, peerTimeout}
}

// Aggregate runs once and returns the merged view.
func (a *Aggregator) Aggregate(ctx context.Context) MeshView {
	mv := MeshView{GeneratedAt: time.Now(), Observers: map[string]ObserverView{}}
	mv.Observers[a.localHost] = a.localView()

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range a.peers {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			peerCtx, cancel := context.WithTimeout(ctx, a.timeout)
			defer cancel()
			v, err := a.client.Fetch(peerCtx, p)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				mv.Observers[p] = ObserverView{Host: p, Reachable: false, Reason: err.Error()}
				return
			}
			v.Reachable = true
			mv.Observers[p] = v
		}()
	}
	wg.Wait()
	return mv
}

func (a *Aggregator) localView() ObserverView {
	v := ObserverView{Host: a.localHost, Reachable: true, Samples: map[string]map[probe.Protocol]Sample{}}
	for _, k := range a.store.Keys() {
		samples := a.store.Snapshot(k.Peer, k.Protocol)
		state := classifier.Classify(samples, a.window, a.threshold)
		var lastTS time.Time
		if len(samples) > 0 {
			lastTS = samples[len(samples)-1].Timestamp
		}
		if v.Samples[k.Peer] == nil {
			v.Samples[k.Peer] = map[probe.Protocol]Sample{}
		}
		v.Samples[k.Peer][k.Protocol] = Sample{State: state, LastTS: lastTS}
	}
	return v
}
