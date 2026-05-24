package http

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/probe"
)

func newTestServer(body string, status int) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/probe") {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestProbeOKWhenBodyMatches(t *testing.T) {
	ts := newTestServer("mesh-checker 0.1.0\n", 200)
	defer ts.Close()
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())

	p := New(pool, 2*time.Second)
	res, err := p.Probe(context.Background(), probe.Target{HTTPSURL: ts.URL + "/probe"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Errorf("expected OK, got %+v", res)
	}
}

func TestProbeFailsOnWrongBody(t *testing.T) {
	ts := newTestServer("nope", 200)
	defer ts.Close()
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())

	p := New(pool, 2*time.Second)
	res, _ := p.Probe(context.Background(), probe.Target{HTTPSURL: ts.URL + "/probe"})
	if res.OK {
		t.Errorf("expected failure (wrong body), got OK")
	}
}

func TestProbeFailsOnUntrustedCert(t *testing.T) {
	ts := newTestServer("mesh-checker 0.1.0\n", 200)
	defer ts.Close()

	p := New(x509.NewCertPool(), 2*time.Second)
	res, _ := p.Probe(context.Background(), probe.Target{HTTPSURL: ts.URL + "/probe"})
	if res.OK {
		t.Errorf("expected TLS failure, got OK")
	}
}
