package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/aggregator"
	"github.com/bsmr/mesh-checker/internal/pkg/pki"
	"github.com/bsmr/mesh-checker/internal/pkg/server/interhost"
)

func TestStatusTableContainsPeerName(t *testing.T) {
	ca, _ := pki.GenerateCA("CA", time.Hour)
	hostA, _ := pki.GenerateHostCert(ca, "node-a", []string{"127.0.0.1"}, time.Hour)
	caCertPEM, _, _ := pki.Encode(ca)
	hostCertPEM, hostKeyPEM, _ := pki.Encode(hostA)
	dir := t.TempDir()
	must(t, writeStrict(dir+"/ca.crt", caCertPEM, 0o644))
	must(t, writeStrict(dir+"/node-a.crt", hostCertPEM, 0o644))
	must(t, writeStrict(dir+"/node-a.key", hostKeyPEM, 0o600))

	tlsCert, _ := tls.X509KeyPair(hostCertPEM, hostKeyPEM)
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	deps := interhost.Deps{MeshCA: pool, HostCert: tlsCert, Peers: map[string]bool{"node-a": true},
		FetchLocal: func() aggregator.ObserverView { return aggregator.ObserverView{Host: "node-a", Reachable: true} }}
	ts := httptest.NewUnstartedServer(interhost.NewMux(deps))
	ts.TLS = interhost.ServerTLSConfig(tlsCert, pool)
	ts.StartTLS()
	defer ts.Close()

	port := ts.Listener.Addr().(*net.TCPAddr).Port

	cfg := newConfigSkeleton("node-a", "127.0.0.1", dir+"/ca.crt", dir+"/node-a.crt", dir+"/node-a.key", port, 0, 0, 0)
	cfgPath := dir + "/config.json"
	must(t, saveStrict(cfgPath, cfg))

	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(), []string{"status", "--config", cfgPath}, &stdout, &stderr); err != nil {
		t.Fatalf("status: %v (stderr=%q)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "node-a") {
		t.Errorf("expected node-a in output, got %q", stdout.String())
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
