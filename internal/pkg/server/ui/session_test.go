package ui

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestSessionIssueAndVerify(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)
	s := NewSession(secret, time.Hour)
	tok, err := s.Issue("admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	user, err := s.Verify(tok, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if user != "admin" {
		t.Errorf("user = %q", user)
	}
}

func TestSessionRejectsExpired(t *testing.T) {
	s := NewSession(make([]byte, 32), time.Second)
	tok, _ := s.Issue("admin", time.Now().Add(-time.Hour))
	if _, err := s.Verify(tok, time.Now()); err == nil {
		t.Error("expected expiry error")
	}
}

func TestSessionRejectsTampered(t *testing.T) {
	s := NewSession(make([]byte, 32), time.Hour)
	tok, _ := s.Issue("admin", time.Now())
	bad := strings.Replace(tok, "a", "b", 1)
	if _, err := s.Verify(bad, time.Now()); err == nil {
		t.Error("expected HMAC failure")
	}
}
