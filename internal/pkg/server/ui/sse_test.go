package ui

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/aggregator"
)

type fakeAgg struct{ v aggregator.MeshView }

func (f *fakeAgg) Aggregate(ctx context.Context) aggregator.MeshView { return f.v }

func TestSSEEmitsStatusEvent(t *testing.T) {
	agg := &fakeAgg{v: aggregator.MeshView{GeneratedAt: time.Now(), Observers: map[string]aggregator.ObserverView{}}}
	h := NewSSEHandler(agg, 20*time.Millisecond)

	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	sc := bufio.NewScanner(resp.Body)
	gotEvent := false
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "event: status") {
			gotEvent = true
			break
		}
	}
	if !gotEvent {
		t.Errorf("no status event seen")
	}
}
