package interhost

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/aggregator"
	"github.com/bsmr/mesh-checker/internal/pkg/pki"
)

func TestClientFetchesViewFromServer(t *testing.T) {
	ca, _ := pki.GenerateCA("CA", time.Hour)
	srvCert, pool := mintTestPKI(t, "node-a", ca)
	clCert, _ := mintTestPKI(t, "node-b", ca)

	deps := Deps{MeshCA: pool, HostCert: srvCert, Peers: map[string]bool{"node-b": true},
		FetchLocal: func() aggregator.ObserverView { return aggregator.ObserverView{Host: "node-a"} }}
	ts := httptest.NewUnstartedServer(NewMux(deps))
	ts.TLS = ServerTLSConfig(srvCert, pool)
	ts.StartTLS()
	defer ts.Close()

	c := NewClient(pool, clCert, map[string]string{"node-a": ts.URL})
	v, err := c.Fetch(context.Background(), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if v.Host != "node-a" {
		t.Errorf("host = %q", v.Host)
	}
}
