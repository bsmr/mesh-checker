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
