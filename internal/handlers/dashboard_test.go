package handlers

import (
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

func TestDashboardStats(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var p1, p2 int64
	res, _ := db.Exec("INSERT INTO providers (name) VALUES ('Gemini')")
	p1, _ = res.LastInsertId()
	res, _ = db.Exec("INSERT INTO providers (name) VALUES ('OpenAI')")
	p2, _ = res.LastInsertId()

	auth := security.NewAuth(db)
	if err := auth.Setup("hunter2"); err != nil {
		t.Fatal(err)
	}

	sm := security.NewSessionManager(auth, 15*time.Minute)
	kh := &KeysHandler{DB: db, Auth: auth}
	dh := &DashboardHandler{DB: db}
	mux := http.NewServeMux()
	mux.Handle("POST /api/keys", RequireSession(sm, http.HandlerFunc(kh.Create)))
	mux.Handle("GET /api/dashboard", RequireSession(sm, http.HandlerFunc(dh.Stats)))

	rec := httptest.NewRecorder()
	s, _ := sm.Create(rec)
	cookie := rec.Result().Cookies()[0]

	post := func(email string, provID int64, key string) {
		body := fmt.Sprintf(`{"email":%q,"provider_id":%d,"key":%q}`, email, provID, key)
		req := httptest.NewRequest(http.MethodPost, "http://x/api/keys", strings.NewReader(body))
		req.AddCookie(cookie)
		req.Header.Set(security.CSRFHeader, s.CSRF)
		r := httptest.NewRecorder()
		mux.ServeHTTP(r, req)
		if r.Code != http.StatusCreated {
			t.Fatalf("create key: %d %s", r.Code, r.Body)
		}
	}
	post("alice@example.com", p1, "sk-1")
	post("alice@example.com", p2, "sk-2")
	post("bob@example.com", p1, "sk-3")

	req := httptest.NewRequest(http.MethodGet, "http://x/api/dashboard", nil)
	req.AddCookie(cookie)
	r := httptest.NewRecorder()
	mux.ServeHTTP(r, req)
	if r.Code != http.StatusOK {
		t.Fatalf("dashboard: %d %s", r.Code, r.Body)
	}
	var resp dashboardResponse
	if err := json.Unmarshal(r.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.TotalKeys != 3 {
		t.Fatalf("total_keys = %d, want 3", resp.TotalKeys)
	}
	if resp.TotalProviders != 2 {
		t.Fatalf("total_providers = %d, want 2", resp.TotalProviders)
	}
	if resp.TotalEmails != 2 {
		t.Fatalf("total_emails = %d, want 2", resp.TotalEmails)
	}
	if len(resp.RecentKeys) != 3 {
		t.Fatalf("recent_keys = %d, want 3", len(resp.RecentKeys))
	}
	if len(resp.RecentModified) != 3 {
		t.Fatalf("recent_modified = %d, want 3", len(resp.RecentModified))
	}
	for _, k := range resp.RecentKeys {
		if k.Key != maskedKey {
			t.Fatalf("recent key not masked: %q", k.Key)
		}
	}
}
