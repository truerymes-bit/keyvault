package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"keyvault/internal/database"
	"keyvault/internal/security"
)

// TestInfoHandler checks GET /api/info returns the expected fields and null
// last_backup when no backup has been made yet.
func TestInfoHandler(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	h := &InfoHandler{DB: db, DBPath: dbPath}
	req := httptest.NewRequest(http.MethodGet, "http://x/api/info", nil)
	w := httptest.NewRecorder()
	h.Info(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp["db_file"] != "test.db" {
		t.Errorf("db_file = %q, want %q", resp["db_file"], "test.db")
	}
	if resp["version"] != "1.0.0" {
		t.Errorf("version = %q, want %q", resp["version"], "1.0.0")
	}
	if resp["encryption"] != "AES-256-GCM" {
		t.Errorf("encryption = %q, want %q", resp["encryption"], "AES-256-GCM")
	}
	if resp["db_size_bytes"] == nil {
		t.Error("db_size_bytes missing")
	}
	if resp["last_backup"] != nil {
		t.Errorf("last_backup = %v, want nil", resp["last_backup"])
	}

	// Now record a backup timestamp and verify last_backup appears.
	ts := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.Exec(
		"INSERT INTO settings (key, value) VALUES ('last_backup', ?)",
		ts,
	); err != nil {
		t.Fatal(err)
	}

	w2 := httptest.NewRecorder()
	h.Info(w2, httptest.NewRequest(http.MethodGet, "http://x/api/info", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("status %d", w2.Code)
	}

	var resp2 map[string]interface{}
	if err := json.NewDecoder(w2.Body).Decode(&resp2); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp2["last_backup"] != ts {
		t.Errorf("last_backup = %v, want %q", resp2["last_backup"], ts)
	}
}

// TestInfoHandlerLocked verifies the info endpoint is blocked by RequireSession
// when the vault is locked.
func TestInfoHandlerLocked(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	auth := security.NewAuth(db)
	if err := auth.Setup("hunter2"); err != nil {
		t.Fatal(err)
	}
	sm := security.NewSessionManager(auth, 15*time.Minute)

	h := &InfoHandler{DB: db, DBPath: dbPath}
	mux := http.NewServeMux()
	mux.Handle("GET /api/info", RequireSession(sm, http.HandlerFunc(h.Info)))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://x/api/info", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("locked status = %d, want 401", rec.Code)
	}
}
