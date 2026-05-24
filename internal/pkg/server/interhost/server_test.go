package interhost

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/aggregator"
	"github.com/bsmr/mesh-checker/internal/pkg/pki"
)

func mintTestPKI(t *testing.T, name string, ca *pki.Material) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	host, err := pki.GenerateHostCert(ca, name, []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, _ := pki.Encode(host)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return tlsCert, pool
}

func TestServerAcceptsAuthorisedClientAndReturnsView(t *testing.T) {
	ca, _ := pki.GenerateCA("CA", time.Hour)
	srvCert, pool := mintTestPKI(t, "node-a", ca)
	clCert, _ := mintTestPKI(t, "node-b", ca)

	deps := Deps{
		MeshCA:   pool,
		HostCert: srvCert,
		Peers:    map[string]bool{"node-b": true},
		FetchLocal: func() aggregator.ObserverView {
			return aggregator.ObserverView{Host: "node-a", Reachable: true}
		},
	}
	ts := httptest.NewUnstartedServer(NewMux(deps))
	ts.TLS = ServerTLSConfig(srvCert, pool)
	ts.StartTLS()
	defer ts.Close()

	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{clCert},
	}}}
	resp, err := cl.Get(ts.URL + "/api/peer/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	var v aggregator.ObserverView
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v.Host != "node-a" {
		t.Errorf("host = %q", v.Host)
	}
}

func TestServerRejectsClientWithUnknownCN(t *testing.T) {
	ca, _ := pki.GenerateCA("CA", time.Hour)
	srvCert, pool := mintTestPKI(t, "node-a", ca)
	clCert, _ := mintTestPKI(t, "stranger", ca)

	deps := Deps{MeshCA: pool, HostCert: srvCert, Peers: map[string]bool{"node-b": true},
		FetchLocal: func() aggregator.ObserverView { return aggregator.ObserverView{} }}
	ts := httptest.NewUnstartedServer(NewMux(deps))
	ts.TLS = ServerTLSConfig(srvCert, pool)
	ts.StartTLS()
	defer ts.Close()

	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: pool, Certificates: []tls.Certificate{clCert},
	}}}
	resp, _ := cl.Get(ts.URL + "/api/peer/status")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}
