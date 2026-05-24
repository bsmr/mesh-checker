package udp

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func TestEncodeDecodeRequestRoundTrip(t *testing.T) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	nonce, _ := NewNonce()
	req, err := EncodeRequest(secret, nonce, time.Unix(1700000000, 0), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := DecodeRequest(secret, req)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.HostName != "node-a" {
		t.Errorf("hostName = %q", parsed.HostName)
	}
	if !bytes.Equal(parsed.Nonce[:], nonce[:]) {
		t.Errorf("nonce mismatch")
	}
}

func TestDecodeRequestFailsOnBadHMAC(t *testing.T) {
	secret := make([]byte, 32)
	nonce, _ := NewNonce()
	req, _ := EncodeRequest(secret, nonce, time.Now(), "node-a")
	req[len(req)-1] ^= 0xFF
	if _, err := DecodeRequest(secret, req); err == nil {
		t.Error("expected HMAC verification failure")
	}
}

func TestResponseIsSmallerThanRequest(t *testing.T) {
	secret := make([]byte, 32)
	nonce, _ := NewNonce()
	req, _ := EncodeRequest(secret, nonce, time.Now(), "node-a-long-name")
	resp, _ := EncodeResponse(secret, nonce, time.Now())
	if len(resp) >= len(req) {
		t.Errorf("response (%d) must be < request (%d)", len(resp), len(req))
	}
}

func TestReplayCacheDetectsDuplicate(t *testing.T) {
	c := NewReplayCache(60 * time.Second)
	nonce, _ := NewNonce()
	if c.SeenOrAdd(nonce, time.Now()) {
		t.Error("first call must not be Seen")
	}
	if !c.SeenOrAdd(nonce, time.Now()) {
		t.Error("second call must be Seen")
	}
}

func TestReplayCacheEvictsExpired(t *testing.T) {
	c := NewReplayCache(10 * time.Millisecond)
	nonce, _ := NewNonce()
	c.SeenOrAdd(nonce, time.Now().Add(-time.Hour))
	if c.SeenOrAdd(nonce, time.Now()) {
		t.Error("expired entry should have been evicted")
	}
}
