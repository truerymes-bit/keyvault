package database

import (
	"path/filepath"
	"strings"
	"testing"
)

func openTemp(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "test.db")
}

func TestFreshDBAppliesMigrations(t *testing.T) {
	db, err := Open(openTemp(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("user_version: %v", err)
	}
	if version != len(migrations) {
		t.Fatalf("user_version = %d, want %d", version, len(migrations))
	}

	for _, table := range []string{"providers", "api_keys", "settings"} {
		var name string
		err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Fatalf("table %s missing: %v", table, err)
		}
	}

	var fk int
	if err := db.QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil {
		t.Fatalf("foreign_keys pragma: %v", err)
	}
	if fk != 1 {
		t.Fatal("foreign keys not enabled")
	}
}

func TestReopenIsIdempotent(t *testing.T) {
	path := openTemp(t)
	db, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := db.Exec("INSERT INTO providers (name) VALUES ('Gemini')"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	db.Close()

	db2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	var n int
	if err := db2.QueryRow("SELECT count(*) FROM providers").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("providers count = %d, want 1", n)
	}
}

func TestDuplicateProviderNameDifferentCaseRejected(t *testing.T) {
	db, err := Open(openTemp(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec("INSERT INTO providers (name) VALUES ('Gemini')"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	_, err = db.Exec("INSERT INTO providers (name) VALUES ('GEMINI')")
	if err == nil {
		t.Fatal("expected case-insensitive duplicate to be rejected")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unique") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProviderDeleteRestrictedWhenKeysExist(t *testing.T) {
	db, err := Open(openTemp(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	res, err := db.Exec("INSERT INTO providers (name) VALUES ('OpenAI')")
	if err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	id, _ := res.LastInsertId()
	_, err = db.Exec("INSERT INTO api_keys (email, provider_id, encrypted_key, nonce, fingerprint) VALUES ('a@b.c', ?, x'01', x'02', x'03')", id)
	if err != nil {
		t.Fatalf("insert key: %v", err)
	}
	if _, err := db.Exec("DELETE FROM providers WHERE id = ?", id); err == nil {
		t.Fatal("expected ON DELETE RESTRICT to block provider delete")
	}
}
