package handlers

import (
	"net/http"
	"strings"

	"keyvault/internal/security"
)

// RequireSession blocks unauthenticated access to /api routes. State-changing
// requests must also carry the session's CSRF token. /api/auth/* is exempt.
func RequireSession(sm *security.SessionManager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/auth/") {
			next.ServeHTTP(w, r)
			return
		}
		s := sm.Current(r)
		if s == nil {
			writeErr(w, http.StatusUnauthorized, "locked")
			return
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if r.Header.Get(security.CSRFHeader) != s.CSRF {
				writeErr(w, http.StatusForbidden, "missing or invalid CSRF token")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
