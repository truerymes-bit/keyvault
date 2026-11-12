package security

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"
)

const SessionCookie = "keyvault_session"
const CSRFHeader = "X-CSRF-Token"

var ErrSessionExpired = errors.New("session expired")

// Session is a server-side session. The cookie carries only the ID.
type Session struct {
	ID           string
	CSRF         string
	LastActivity time.Time
}

// SessionManager tracks sessions in memory. A restart clears all sessions,
// which matches the in-memory-only key model.
type SessionManager struct {
	mu       sync.Mutex
	sessions map[string]*Session
	timeout  time.Duration
	auth     *Auth
	now      func() time.Time
}

func NewSessionManager(auth *Auth, timeout time.Duration) *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
		timeout:  timeout,
		auth:     auth,
		now:      time.Now,
	}
}

// Timeout returns the configured idle timeout.
func (m *SessionManager) Timeout() time.Duration { return m.timeout }

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Create starts a new session and sets the session cookie.
func (m *SessionManager) Create(w http.ResponseWriter) (*Session, error) {
	id, err := randomToken()
	if err != nil {
		return nil, err
	}
	csrf, err := randomToken()
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	s := &Session{ID: id, CSRF: csrf, LastActivity: m.now()}
	m.sessions[id] = s
	m.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return s, nil
}

// Current returns the live session for the request, refreshing its activity
// time, or nil. Expired sessions are dropped and the master key is cleared.
func (m *SessionManager) Current(r *http.Request) *Session {
	cookie, err := r.Cookie(SessionCookie)
	if err != nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[cookie.Value]
	if !ok {
		return nil
	}
	now := m.now()
	if now.Sub(s.LastActivity) > m.timeout {
		delete(m.sessions, s.ID)
		m.auth.Lock()
		return nil
	}
	s.LastActivity = now
	return s
}

// Destroy removes the session for the request and clears the cookie.
func (m *SessionManager) Destroy(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(SessionCookie); err == nil {
		m.mu.Lock()
		delete(m.sessions, cookie.Value)
		m.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
