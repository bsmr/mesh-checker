package probe

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bsmr/mesh-checker/internal/pkg/version"
)

func TestHTTPProbeHandlerReturnsBody(t *testing.T) {
	h := NewHTTPHandler()
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/probe")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "mesh-checker") {
		t.Errorf("body = %q", string(b))
	}
	if !strings.Contains(string(b), version.String()) {
		t.Errorf("version not in body: %q", string(b))
	}
}

func TestHTTPProbeRejectsOtherPaths(t *testing.T) {
	h := NewHTTPHandler()
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/foo")
	if resp.StatusCode != 404 {
		t.Errorf("status = %d", resp.StatusCode)
	}
}
