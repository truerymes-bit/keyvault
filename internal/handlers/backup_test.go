package handlers

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keyvault/internal/database"
	"keyvault/internal/security"
)

// TestBackupRestoreRoundTrip seeds a pre-backup database, downloads the
// encrypted backup, mutates the live database, then restores and asserts the
// live connection now sees the backup state (ATTACH-based restore) and a
// rollback snapshot was created.
func TestBackupRestoreRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Pre-backup state: one provider with two keys.
	gemini := seedProvider(t, db, "Gemini", 2)

	auth := security.NewAuth(db)
	if err := auth.Setup("hunter2"); err != nil {
		t.Fatal(err)
	}
	sm := security.NewSessionManager(auth, 15*time.Minute)
	h := &BackupHandler{DB: db, DBPath: dbPath, Auth: auth}
	mux := http.NewServeMux()
	mux.Handle("POST /api/backup", RequireSession(sm, http.HandlerFunc(h.Backup)))
	mux.Handle("POST /api/restore", RequireSession(sm, http.HandlerFunc(h.Restore)))

	do := func(path string, body *bytes.Buffer, contentType string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		s, err := sm.Create(rec)
		if err != nil {
			t.Fatal(err)
		}
		var req *http.Request
		if body != nil {
			req = httptest.NewRequest(http.MethodPost, "http://x"+path, body)
			req.Header.Set("Content-Type", contentType)
		} else {
			req = httptest.NewRequest(http.MethodPost, "http://x"+path, nil)
		}
		req.AddCookie(rec.Result().Cookies()[0])
		req.Header.Set(security.CSRFHeader, s.CSRF)
		out := httptest.NewRecorder()
		mux.ServeHTTP(out, req)
		return out
	}

	// Download the backup.
	rec := do("/api/backup", nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("backup: %d %s", rec.Code, rec.Body)
	}
	backupBytes := rec.Body.Bytes()
	if len(backupBytes) < 1024 {
		t.Fatalf("backup too small: %d bytes", len(backupBytes))
	}

	// Mutate the live database: an extra provider that the backup does not know.
	seedProvider(t, db, "TempProvider", 1)

	// Restore from the downloaded backup.
	var form bytes.Buffer
	writer := multipart.NewWriter(&form)
	file, err := writer.CreateFormFile("backup", "backup.kbk")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(backupBytes); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	rec = do("/api/restore", &form, writer.FormDataContentType())
	if rec.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"status":"restored"`) {
		t.Fatalf("restore body: %s", rec.Body)
	}

	// The live connection must see the backup state: exactly one provider,
	// with both keys, and no TempProvider rows anywhere.
	var providerCount int
	if err := db.QueryRow("SELECT count(*) FROM providers").Scan(&providerCount); err != nil {
		t.Fatal(err)
	}
	if providerCount != 1 {
		t.Fatalf("providers after restore = %d, want 1", providerCount)
	}
	var keyCount int
	if err := db.QueryRow("SELECT count(*) FROM api_keys").Scan(&keyCount); err != nil {
		t.Fatal(err)
	}
	if keyCount != 2 {
		t.Fatalf("keys after restore = %d, want 2", keyCount)
	}
	var owner int64
	if err := db.QueryRow("SELECT provider_id FROM api_keys LIMIT 1").Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if owner != gemini {
		t.Fatalf("restored key provider = %d, want %d", owner, gemini)
	}
	var tempCount int
	if err := db.QueryRow("SELECT count(*) FROM providers WHERE name = 'TempProvider'").Scan(&tempCount); err != nil {
		t.Fatal(err)
	}
	if tempCount != 0 {
		t.Fatalf("temp provider survived restore")
	}

	// A rollback snapshot must exist next to the database.
	entries, err := os.ReadDir(filepath.Dir(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	foundRollback := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "keyvault.db.rollback.") {
			foundRollback = true
		}
	}
	if !foundRollback {
		t.Fatalf("no rollback snapshot in %s", filepath.Dir(dbPath))
	}
}
