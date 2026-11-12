package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keyvault/internal/database"
	"keyvault/internal/security"
)

func testEnv(t *testing.T, timeout time.Duration) (*security.SessionManager, *http.Handler) {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	auth := security.NewAuth(db)
	if err := auth.Setup("hunter2"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	sm := security.NewSessionManager(auth, timeout)
	protected := RequireSession(sm, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "secret")
	}))
	return sm, &protected
}

func unlockCookie(t *testing.T, sm *security.SessionManager) (*http.Cookie, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	s, err := sm.Create(rec)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	res := rec.Result()
	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	cookies[0].Path = ""
	_ = s
	return cookies[0], s.CSRF
}

func TestLockedAccessRefused(t *testing.T) {
	_, protected := testEnv(t, 15*time.Minute)
	req := httptest.NewRequest(http.MethodGet, "http://x/api/keys", nil)
	rec := httptest.NewRecorder()
	(*protected).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestMissingCSRFRefused(t *testing.T) {
	sm, protected := testEnv(t, 15*time.Minute)
	cookie, _ := unlockCookie(t, sm)
	req := httptest.NewRequest(http.MethodPost, "http://x/api/keys", strings.NewReader(`{}`))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	(*protected).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestValidCSRFAccepted(t *testing.T) {
	sm, protected := testEnv(t, 15*time.Minute)
	cookie, csrf := unlockCookie(t, sm)
	req := httptest.NewRequest(http.MethodPost, "http://x/api/keys", strings.NewReader(`{}`))
	req.AddCookie(cookie)
	req.Header.Set(security.CSRFHeader, csrf)
	rec := httptest.NewRecorder()
	(*protected).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestExpiredSessionRefused(t *testing.T) {
	sm, protected := testEnv(t, 50*time.Millisecond)
	cookie, _ := unlockCookie(t, sm)
	time.Sleep(80 * time.Millisecond)
	req := httptest.NewRequest(http.MethodGet, "http://x/api/keys", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	(*protected).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestSessionCookieFlags(t *testing.T) {
	sm, _ := testEnv(t, 15*time.Minute)
	rec := httptest.NewRecorder()
	if _, err := sm.Create(rec); err != nil {
		t.Fatalf("create: %v", err)
	}
	res := rec.Result()
	cookies := res.Cookies()
	if len(cookies) != 1 {
		t.Fatal("expected cookie")
	}
	c := cookies[0]
	if !c.HttpOnly {
		t.Fatal("cookie must be HttpOnly")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Fatal("cookie must be SameSite=Strict")
	}
	if c.Path != "/" {
		t.Fatalf("cookie path = %q, want /", c.Path)
	}
}
