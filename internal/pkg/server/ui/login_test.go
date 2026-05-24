package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/bsmr/mesh-checker/internal/pkg/config"
)

func mkUsers(t *testing.T, name, password string) []config.User {
	h, err := bcrypt.GenerateFromPassword([]byte(password), 4)
	if err != nil {
		t.Fatal(err)
	}
	return []config.User{{Name: name, PasswordHash: string(h)}}
}

func TestLoginSetsCookieOnGoodCreds(t *testing.T) {
	users := mkUsers(t, "admin", "s3cret!")
	sess := NewSession(make([]byte, 32), time.Hour)
	h := NewLoginHandler(users, sess, 1*time.Millisecond)

	body := url.Values{"name": {"admin"}, "password": {"s3cret!"}}.Encode()
	req := httptest.NewRequest("POST", "/ui/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != cookieName {
		t.Fatalf("cookies = %v", cookies)
	}
	if !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie not hardened: %+v", cookies[0])
	}
}

func TestLoginRejectsBadCreds(t *testing.T) {
	users := mkUsers(t, "admin", "s3cret!")
	sess := NewSession(make([]byte, 32), time.Hour)
	h := NewLoginHandler(users, sess, 1*time.Millisecond)
	body := url.Values{"name": {"admin"}, "password": {"wrong"}}.Encode()
	req := httptest.NewRequest("POST", "/ui/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}
