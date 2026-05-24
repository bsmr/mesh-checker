package version

import (
	"strings"
	"testing"
)

func TestStringMatchesEmbeddedFile(t *testing.T) {
	v := String()
	if v == "" {
		t.Fatal("version string is empty")
	}
	if strings.ContainsAny(v, " \t\r\n") {
		t.Errorf("version string has whitespace: %q", v)
	}
}
