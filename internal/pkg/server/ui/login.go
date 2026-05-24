package ui

import (
	"crypto/subtle"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/bsmr/mesh-checker/internal/pkg/config"
)

const cookieName = "mesh-session"

type loginHandler struct {
	users     []config.User
	session   *Session
	failDelay time.Duration
}

func NewLoginHandler(users []config.User, sess *Session, failDelay time.Duration) http.Handler {
	return &loginHandler{users: users, session: sess, failDelay: failDelay}
}

func (h *loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	name := r.FormValue("name")
	password := r.FormValue("password")
	if h.authenticate(name, password) {
		tok, err := h.session.Issue(name, time.Now())
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name: cookieName, Value: tok,
			Path: "/ui/", HttpOnly: true, Secure: true,
			SameSite: http.SameSiteStrictMode,
		})
		http.Redirect(w, r, "/ui/", http.StatusSeeOther)
		return
	}
	time.Sleep(h.failDelay)
	http.Error(w, "unauthorised", http.StatusUnauthorized)
}

func (h *loginHandler) authenticate(name, password string) bool {
	for _, u := range h.users {
		if subtle.ConstantTimeCompare([]byte(u.Name), []byte(name)) == 1 {
			if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err == nil {
				return true
			}
		}
	}
	return false
}
