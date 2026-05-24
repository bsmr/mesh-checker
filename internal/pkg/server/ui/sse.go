package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/aggregator"
)

// Aggregator is the subset of aggregator.Aggregator the SSE handler uses.
type Aggregator interface {
	Aggregate(ctx context.Context) aggregator.MeshView
}

type sseHandler struct {
	agg      Aggregator
	interval time.Duration
}

func NewSSEHandler(agg Aggregator, interval time.Duration) http.Handler {
	return &sseHandler{agg: agg, interval: interval}
}

func (h *sseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	ctx := r.Context()
	t := time.NewTicker(h.interval)
	defer t.Stop()
	h.emit(w, flusher, ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.emit(w, flusher, ctx)
		}
	}
}

func (h *sseHandler) emit(w http.ResponseWriter, f http.Flusher, ctx context.Context) {
	view := h.agg.Aggregate(ctx)
	b, err := json.Marshal(view)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "event: status\ndata: %s\n\n", b)
	f.Flush()
}
