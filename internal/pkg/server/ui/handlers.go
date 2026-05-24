package ui

import (
	"io/fs"
	"net/http"
	"strings"
	"time"

	serverprobe "github.com/bsmr/mesh-checker/internal/pkg/server/probe"
	"github.com/bsmr/mesh-checker/internal/pkg/version"
)

// Deps is the wiring struct for NewMux. nil fields disable features.
type Deps struct {
	Login   http.Handler
	SSE     http.Handler
	Session *Session
}

// NewMux assembles the UI listener's full mux.
func NewMux(d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/probe", serverprobe.NewHTTPHandler())
	mux.HandleFunc("/ui/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && d.Login != nil {
			d.Login.ServeHTTP(w, r)
			return
		}
		serveStatic(w, r, "static/login.html", "text/html; charset=utf-8")
	})
	mux.HandleFunc("/ui/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", MaxAge: -1, Path: "/ui/"})
		http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
	})
	mux.HandleFunc("/ui/assets/", func(w http.ResponseWriter, r *http.Request) {
		name := "static/" + r.URL.Path[len("/ui/assets/"):]
		serveStatic(w, r, name, contentTypeFor(name))
	})
	mux.Handle("/ui/", authMiddleware(d.Session, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ui/" {
			http.NotFound(w, r)
			return
		}
		serveStatic(w, r, "static/index.html", "text/html; charset=utf-8")
	})))
	if d.SSE != nil {
		mux.Handle("/ui/sse/status", authMiddleware(d.Session, d.SSE))
	}
	return withCommonHeaders(mux)
}

func contentTypeFor(name string) string {
	switch {
	case strings.HasSuffix(name, ".js"):
		return "application/javascript"
	case strings.HasSuffix(name, ".css"):
		return "text/css"
	case strings.HasSuffix(name, ".html"):
		return "text/html; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

func serveStatic(w http.ResponseWriter, r *http.Request, name, contentType string) {
	b, err := fs.ReadFile(staticFS, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Mesh-Checker-Version", version.String())
	w.Write(b) //nolint:errcheck
}

func withCommonHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		h.ServeHTTP(w, r)
	})
}

func authMiddleware(sess *Session, next http.Handler) http.Handler {
	if sess == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "auth not configured", http.StatusUnauthorized)
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			redirectOrUnauth(w, r)
			return
		}
		user, err := sess.Verify(c.Value, time.Now())
		if err != nil {
			redirectOrUnauth(w, r)
			return
		}
		r.Header.Set("X-Mesh-User", user)
		next.ServeHTTP(w, r)
	})
}

func redirectOrUnauth(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
		return
	}
	w.Header().Set("WWW-Authenticate", "Cookie")
	http.Error(w, "unauthorised", http.StatusUnauthorized)
}
