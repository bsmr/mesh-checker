package version

import (
	"strings"
	"testing"
)

func TestStringNonEmptyAndTrimmed(t *testing.T) {
	v := String()
	if v == "" {
		t.Fatal("version string is empty")
	}
	if strings.ContainsAny(v, " \t\r\n") {
		t.Errorf("version string has whitespace: %q", v)
	}
}

func TestStringDefaultsToDev(t *testing.T) {
	// When tests run without -ldflags injection, version should be "dev".
	// CI or release builds that inject a real version will not run this
	// assertion in test context (tests run with the default).
	if got := String(); got != "dev" {
		t.Errorf("got %q, want %q (unstamped test build)", got, "dev")
	}
}
