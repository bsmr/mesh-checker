// Package udp contains the UDP probe wire format, HMAC verification,
// and a nonce replay cache. The client side (Prober) and server side
// (echo) both consume these primitives.
package udp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

const (
	nonceLen = 16
	tsLen    = 8
	hmacLen  = 32
)

// Nonce is a 16-byte random value used to prevent replay attacks.
type Nonce [nonceLen]byte

// NewNonce generates a cryptographically random Nonce.
func NewNonce() (Nonce, error) {
	var n Nonce
	_, err := rand.Read(n[:])
	return n, err
}

// Request represents a decoded UDP probe request.
type Request struct {
	Nonce     Nonce
	Timestamp time.Time
	HostName  string
}

// EncodeRequest serializes a request into the wire format:
// nonce(16) || ts(8, BE unix nano) || hostName(...) || HMAC-SHA256(...)(32)
func EncodeRequest(secret []byte, nonce Nonce, ts time.Time, hostName string) ([]byte, error) {
	if len(hostName) == 0 {
		return nil, errors.New("udp: hostName must not be empty")
	}
	body := make([]byte, 0, nonceLen+tsLen+len(hostName)+hmacLen)
	body = append(body, nonce[:]...)
	tsBuf := make([]byte, tsLen)
	binary.BigEndian.PutUint64(tsBuf, uint64(ts.UnixNano()))
	body = append(body, tsBuf...)
	body = append(body, []byte(hostName)...)
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	body = mac.Sum(body)
	return body, nil
}

// DecodeRequest verifies the HMAC and deserializes a request from the wire format.
func DecodeRequest(secret, buf []byte) (Request, error) {
	if len(buf) < nonceLen+tsLen+1+hmacLen {
		return Request{}, errors.New("udp: request too short")
	}
	macStart := len(buf) - hmacLen
	mac := hmac.New(sha256.New, secret)
	mac.Write(buf[:macStart])
	if !hmac.Equal(mac.Sum(nil), buf[macStart:]) {
		return Request{}, errors.New("udp: hmac mismatch")
	}
	var n Nonce
	copy(n[:], buf[:nonceLen])
	tsNs := binary.BigEndian.Uint64(buf[nonceLen : nonceLen+tsLen])
	return Request{
		Nonce:     n,
		Timestamp: time.Unix(0, int64(tsNs)),
		HostName:  string(buf[nonceLen+tsLen : macStart]),
	}, nil
}

// EncodeResponse serializes a response into the wire format:
// nonce(16) || ts(8) || HMAC(32). Strictly smaller than a request
// (no hostName field) for anti-amplification.
func EncodeResponse(secret []byte, nonce Nonce, ts time.Time) ([]byte, error) {
	body := make([]byte, 0, nonceLen+tsLen+hmacLen)
	body = append(body, nonce[:]...)
	tsBuf := make([]byte, tsLen)
	binary.BigEndian.PutUint64(tsBuf, uint64(ts.UnixNano()))
	body = append(body, tsBuf...)
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	body = mac.Sum(body)
	return body, nil
}

// DecodeResponse verifies the HMAC and deserializes a response from the wire format.
func DecodeResponse(secret, buf []byte) (Nonce, time.Time, error) {
	if len(buf) != nonceLen+tsLen+hmacLen {
		return Nonce{}, time.Time{}, errors.New("udp: response wrong length")
	}
	macStart := len(buf) - hmacLen
	mac := hmac.New(sha256.New, secret)
	mac.Write(buf[:macStart])
	if !hmac.Equal(mac.Sum(nil), buf[macStart:]) {
		return Nonce{}, time.Time{}, errors.New("udp: response hmac mismatch")
	}
	var n Nonce
	copy(n[:], buf[:nonceLen])
	tsNs := binary.BigEndian.Uint64(buf[nonceLen : nonceLen+tsLen])
	return n, time.Unix(0, int64(tsNs)), nil
}

// ReplayCache rejects repeated nonces within the TTL window.
type ReplayCache struct {
	ttl  time.Duration
	mu   sync.Mutex
	seen map[Nonce]time.Time
}

// NewReplayCache creates a ReplayCache that evicts entries older than ttl.
func NewReplayCache(ttl time.Duration) *ReplayCache {
	return &ReplayCache{ttl: ttl, seen: map[Nonce]time.Time{}}
}

// SeenOrAdd returns true if the nonce was already seen within the TTL window,
// and adds it to the cache if not. Expired entries are evicted on each call.
func (c *ReplayCache) SeenOrAdd(n Nonce, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := now.Add(-c.ttl)
	for k, t := range c.seen {
		if t.Before(cutoff) {
			delete(c.seen, k)
		}
	}
	if _, ok := c.seen[n]; ok {
		return true
	}
	c.seen[n] = now
	return false
}
