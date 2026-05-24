package classifier

import (
	"testing"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

func mkResults(oks ...bool) []probe.Result {
	out := make([]probe.Result, len(oks))
	for i, ok := range oks {
		out[i] = probe.Result{OK: ok}
	}
	return out
}

func TestUpWhenAllPass(t *testing.T) {
	got := Classify(mkResults(true, true, true, true, true), 5, 3)
	if got != Up {
		t.Errorf("got %v, want Up", got)
	}
}

func TestDownWhenThresholdFailures(t *testing.T) {
	got := Classify(mkResults(false, false, false, true, true), 5, 3)
	if got != Down {
		t.Errorf("got %v, want Down", got)
	}
}

func TestDegradedWhenSomeFail(t *testing.T) {
	got := Classify(mkResults(true, false, true, true, true), 5, 3)
	if got != Degraded {
		t.Errorf("got %v, want Degraded", got)
	}
}

func TestUnknownWhenInsufficientSamples(t *testing.T) {
	got := Classify(mkResults(true, true), 5, 3)
	if got != Unknown {
		t.Errorf("got %v, want Unknown", got)
	}
}

func TestUsesOnlyTailWhenMoreSamplesThanWindow(t *testing.T) {
	got := Classify(mkResults(false, false, false, false, false, true, true, true, true, true), 5, 3)
	if got != Up {
		t.Errorf("got %v, want Up", got)
	}
}
