package aggregator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/classifier"
	"github.com/bsmr/mesh-checker/internal/pkg/probe"
	"github.com/bsmr/mesh-checker/internal/pkg/store"
)

type fakeClient struct {
	views map[string]ObserverView
	err   map[string]error
}

func (f *fakeClient) Fetch(ctx context.Context, peer string) (ObserverView, error) {
	if e, ok := f.err[peer]; ok && e != nil {
		return ObserverView{}, e
	}
	return f.views[peer], nil
}

// panicClient panics on any Fetch call, proving that LocalView never fans out.
type panicClient struct{}

func (p *panicClient) Fetch(_ context.Context, peer string) (ObserverView, error) {
	panic("panicClient.Fetch called for peer " + peer + " — LocalView must not fan out")
}

func TestLocalViewReturnsOnlyLocalStateNoFanOut(t *testing.T) {
	st := store.New(5)
	st.Append("node-b", probe.TCP, probe.Result{OK: true})
	// Use a client that PANICS if called — proves LocalView does no fan-out.
	a := New(&panicClient{}, st, "node-a", []string{"node-b"}, 5, 3, 100*time.Millisecond)
	v := a.LocalView()
	if v.Host != "node-a" {
		t.Errorf("host = %q", v.Host)
	}
	if !v.Reachable {
		t.Error("local view should always be Reachable=true")
	}
	if _, ok := v.Samples["node-b"]; !ok {
		t.Error("expected node-b in local view samples")
	}
}

func TestAggregateIncludesLocalAndPeers(t *testing.T) {
	st := store.New(5)
	st.Append("node-b", probe.TCP, probe.Result{OK: true})
	cl := &fakeClient{views: map[string]ObserverView{
		"node-b": {Host: "node-b", Samples: map[string]map[probe.Protocol]Sample{
			"node-a": {probe.TCP: {State: classifier.Up}},
		}},
	}}
	a := New(cl, st, "node-a", []string{"node-b"}, 5, 3, 100*time.Millisecond)
	mv := a.Aggregate(context.Background())
	if _, ok := mv.Observers["node-a"]; !ok {
		t.Fatal("local view missing")
	}
	if _, ok := mv.Observers["node-b"]; !ok {
		t.Fatal("peer view missing")
	}
}

func TestAggregateMarksUnreachablePeer(t *testing.T) {
	st := store.New(5)
	cl := &fakeClient{err: map[string]error{"node-b": errors.New("conn refused")}}
	a := New(cl, st, "node-a", []string{"node-b"}, 5, 3, 50*time.Millisecond)
	mv := a.Aggregate(context.Background())
	v, ok := mv.Observers["node-b"]
	if !ok {
		t.Fatal("peer placeholder missing")
	}
	if v.Reachable {
		t.Error("expected Reachable=false")
	}
	if v.Reason == "" {
		t.Error("expected non-empty Reason")
	}
}
