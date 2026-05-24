package probe

import (
	"context"
	"testing"
	"time"
)

type fakeProber struct{ ok bool }

func (f *fakeProber) Probe(ctx context.Context, t Target) (Result, error) {
	return Result{Timestamp: time.Now(), Latency: 1, OK: f.ok}, nil
}

func TestProberInterfaceSatisfied(t *testing.T) {
	var _ Prober = (*fakeProber)(nil)
}

func TestResultZeroValueIsFailure(t *testing.T) {
	var r Result
	if r.OK {
		t.Error("zero-value Result.OK must be false")
	}
}
