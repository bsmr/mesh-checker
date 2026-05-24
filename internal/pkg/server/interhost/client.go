package interhost

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/bsmr/mesh-checker/internal/pkg/aggregator"
)

// Client fetches ObserverViews from remote peers over mTLS.
type Client struct {
	urls   map[string]string // peer name -> base URL
	client *http.Client
}

// NewClient constructs a Client that authenticates with cert and
// verifies server certificates against caPool.
func NewClient(caPool *x509.CertPool, cert tls.Certificate, peerURLs map[string]string) *Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}}
	return &Client{urls: peerURLs, client: &http.Client{Transport: tr, Timeout: 5 * time.Second}}
}

// Fetch retrieves the ObserverView from the named peer. It satisfies
// the aggregator.PeerClient interface.
func (c *Client) Fetch(ctx context.Context, peer string) (aggregator.ObserverView, error) {
	base, ok := c.urls[peer]
	if !ok {
		return aggregator.ObserverView{}, fmt.Errorf("interhost: no URL configured for peer %q", peer)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/api/peer/status", nil)
	if err != nil {
		return aggregator.ObserverView{}, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return aggregator.ObserverView{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return aggregator.ObserverView{}, fmt.Errorf("interhost: peer %q returned %d", peer, resp.StatusCode)
	}
	var v aggregator.ObserverView
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return aggregator.ObserverView{}, err
	}
	return v, nil
}
