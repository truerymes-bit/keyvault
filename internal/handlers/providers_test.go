package handlers

import (
	"bytes"
	"encoding/json"
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

type providersTestEnv struct {
	t      *testing.T
	mux    *http.ServeMux
	cookie *http.Cookie
	csrf   string
}

func newProvidersEnv(t *testing.T) *providersTestEnv {
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
	sm := security.NewSessionManager(auth, 15*time.Minute)
	h := &ProvidersHandler{DB: db}
	protected := func(fn http.HandlerFunc) http.Handler {
		return RequireSession(sm, fn)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /api/providers", protected(h.List))
	mux.Handle("GET /api/providers/{id}", protected(h.Get))
	mux.Handle("POST /api/providers", protected(h.Create))
	mux.Handle("PUT /api/providers/{id}", protected(h.Update))
	mux.Handle("DELETE /api/providers/{id}", protected(h.Delete))
	mux.Handle("PUT /api/providers/{id}/notes", protected(h.UpdateNotes))

	rec := httptest.NewRecorder()
	s, err := sm.Create(rec)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return &providersTestEnv{
		t:      t,
		mux:    mux,
		cookie: rec.Result().Cookies()[0],
		csrf:   s.CSRF,
	}
}

func (e *providersTestEnv) do(method, path, body string, withCSRF bool) *httptest.ResponseRecorder {
	e.t.Helper()
	var rdr *bytes.Reader
	if body != "" {
		rdr = bytes.NewReader([]byte(body))
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, "http://x"+path, rdr)
	req.AddCookie(e.cookie)
	if withCSRF {
		req.Header.Set(security.CSRFHeader, e.csrf)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func TestProvidersCRUD(t *testing.T) {
	e := newProvidersEnv(t)

	rec := e.do(http.MethodPost, "/api/providers", `{"name":"Gemini"}`, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created providerJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created.Name != "Gemini" || created.ID == 0 {
		t.Fatalf("unexpected created: %+v", created)
	}

	rec = e.do(http.MethodGet, "/api/providers", "", false)
	var list []providerJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 1 || list[0].Name != "Gemini" {
		t.Fatalf("list: %+v", list)
	}

	rec = e.do(http.MethodGet, fmt.Sprintf("/api/providers/%d", created.ID), "", false)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: %d", rec.Code)
	}

	rec = e.do(http.MethodPut, fmt.Sprintf("/api/providers/%d", created.ID), `{"name":"Gemini Pro"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	var updated providerJSON
	_ = json.Unmarshal(rec.Body.Bytes(), &updated)
	if updated.Name != "Gemini Pro" {
		t.Fatalf("updated name: %q", updated.Name)
	}

	rec = e.do(http.MethodDelete, fmt.Sprintf("/api/providers/%d", created.ID), "", true)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	rec = e.do(http.MethodGet, fmt.Sprintf("/api/providers/%d", created.ID), "", false)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete: %d", rec.Code)
	}
}

func TestProvidersCaseInsensitiveUniqueness(t *testing.T) {
	e := newProvidersEnv(t)
	if rec := e.do(http.MethodPost, "/api/providers", `{"name":"Gemini"}`, true); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d", rec.Code)
	}
	rec := e.do(http.MethodPost, "/api/providers", `{"name":"GEMINI"}`, true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("case-variant create: %d, want 409", rec.Code)
	}
}

func TestProvidersEmptyNameRejected(t *testing.T) {
	e := newProvidersEnv(t)
	rec := e.do(http.MethodPost, "/api/providers", `{"name":"   "}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty name: %d, want 400", rec.Code)
	}
}

func TestProviderDeleteWithKeysReturns409(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res, err := db.Exec("INSERT INTO providers (name) VALUES ('OpenAI')")
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := res.LastInsertId()
	db.Exec("INSERT INTO api_keys (email, provider_id, encrypted_key, nonce, fingerprint) VALUES ('a@b.c', ?, x'01', x'02', x'03')", pid)
	db.Exec("INSERT INTO api_keys (email, provider_id, encrypted_key, nonce, fingerprint) VALUES ('d@e.f', ?, x'04', x'05', x'06')", pid)

	auth := security.NewAuth(db)
	if err := auth.Setup("pw"); err != nil {
		t.Fatal(err)
	}
	sm := security.NewSessionManager(auth, 15*time.Minute)
	h := &ProvidersHandler{DB: db}
	mux := http.NewServeMux()
	mux.Handle("DELETE /api/providers/{id}", RequireSession(sm, http.HandlerFunc(h.Delete)))

	rec := httptest.NewRecorder()
	s, _ := sm.Create(rec)
	cookie := rec.Result().Cookies()[0]

	req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("http://x/api/providers/%d", pid), nil)
	req.AddCookie(cookie)
	req.Header.Set(security.CSRFHeader, s.CSRF)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("delete with keys: %d, want 409", rec2.Code)
	}
	if !strings.Contains(rec2.Body.String(), `"key_count":2`) {
		t.Fatalf("body should carry key_count 2: %s", rec2.Body)
	}
}

func TestNotesPersist(t *testing.T) {
	e := newProvidersEnv(t)
	rec := e.do(http.MethodPost, "/api/providers", `{"name":"ElevenLabs"}`, true)
	var created providerJSON
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	notes := "Model ID: eleven_v4\nVoice ID: abc123"
	rec = e.do(http.MethodPut, fmt.Sprintf("/api/providers/%d/notes", created.ID),
		`{"notes":"`+strings.ReplaceAll(notes, "\n", "\\n")+`"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("notes update: %d %s", rec.Code, rec.Body)
	}
	rec = e.do(http.MethodGet, fmt.Sprintf("/api/providers/%d", created.ID), "", false)
	var got providerJSON
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Notes != notes {
		t.Fatalf("notes = %q, want %q", got.Notes, notes)
	}
}

func TestProvidersLockedRefused(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	auth := security.NewAuth(db)
	sm := security.NewSessionManager(auth, 15*time.Minute)
	h := &ProvidersHandler{DB: db}
	mux := http.NewServeMux()
	mux.Handle("GET /api/providers", RequireSession(sm, http.HandlerFunc(h.List)))
	req := httptest.NewRequest(http.MethodGet, "http://x/api/providers", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("locked: %d, want 401", rec.Code)
	}
}
