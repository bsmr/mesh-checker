package recoverwrap

import (
	"context"
	"log/slog"
	"strings"
	"testing"
)

// notifyHandler wraps a slog.Handler and closes notify after the first Handle call.
type notifyHandler struct {
	slog.Handler
	notify chan<- string
}

func (h *notifyHandler) Handle(ctx context.Context, r slog.Record) error {
	err := h.Handler.Handle(ctx, r)
	// Build a quick string of all attrs for assertion.
	var sb strings.Builder
	sb.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		sb.WriteString(" ")
		sb.WriteString(a.Key)
		sb.WriteString("=")
		sb.WriteString(a.Value.String())
		return true
	})
	select {
	case h.notify <- sb.String():
	default:
	}
	return err
}

func TestGoRecoversAndLogs(t *testing.T) {
	notify := make(chan string, 1)
	inner := slog.NewTextHandler(io_discard{}, nil)
	slog.SetDefault(slog.New(&notifyHandler{Handler: inner, notify: notify}))

	Go("test-scope", func() {
		panic("boom")
	})

	out := <-notify
	if !strings.Contains(out, "test-scope") {
		t.Errorf("log should mention scope; got %q", out)
	}
	if !strings.Contains(out, "boom") {
		t.Errorf("log should mention panic value; got %q", out)
	}
}

// io_discard implements io.Writer, discarding all output.
type io_discard struct{}

func (io_discard) Write(p []byte) (int, error) { return len(p), nil }

func TestGoLetsNormalCompletionThrough(t *testing.T) {
	done := make(chan int, 1)
	Go("ok", func() { done <- 42 })
	if v := <-done; v != 42 {
		t.Errorf("got %d", v)
	}
}
