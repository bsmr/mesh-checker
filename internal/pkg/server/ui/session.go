// Package ui implements the authenticated UI listener.
package ui

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Session struct {
	secret []byte
	ttl    time.Duration
}

func NewSession(secret []byte, ttl time.Duration) *Session {
	return &Session{secret: secret, ttl: ttl}
}

func (s *Session) Issue(user string, now time.Time) (string, error) {
	if strings.ContainsAny(user, ":|") {
		return "", errors.New("ui: user name contains forbidden char")
	}
	exp := now.Add(s.ttl).Unix()
	payload := fmt.Sprintf("%s:%d", user, exp)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(append([]byte(payload+":"), sig...)), nil
}

func (s *Session) Verify(token string, now time.Time) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}
	if len(raw) <= 33 {
		return "", errors.New("ui: token too short")
	}
	macStart := len(raw) - 32
	if raw[macStart-1] != ':' {
		return "", errors.New("ui: token malformed")
	}
	payload := raw[:macStart-1]
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), raw[macStart:]) {
		return "", errors.New("ui: hmac mismatch")
	}
	parts := strings.SplitN(string(payload), ":", 2)
	if len(parts) != 2 {
		return "", errors.New("ui: payload malformed")
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", err
	}
	if now.Unix() >= exp {
		return "", errors.New("ui: session expired")
	}
	return parts[0], nil
}
