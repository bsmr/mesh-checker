package ui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProbeHandlerOnUIListener(t *testing.T) {
	mux := NewMux(Deps{})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/probe")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "mesh-checker") {
		t.Errorf("body = %q", string(b))
	}
}

func TestIndexRequiresAuth(t *testing.T) {
	mux := NewMux(Deps{})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := c.Get(srv.URL + "/ui/")
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d (want 401 or 303)", resp.StatusCode)
	}
}

func TestLoginPageServedUnauthenticated(t *testing.T) {
	mux := NewMux(Deps{})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/ui/login")
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
}
