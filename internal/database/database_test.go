package database

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
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

// indexColumns maps each index name on table to its column names in index
// order. Index names come from sqlite_master (trusted, not user input).
func indexColumns(t *testing.T, db *sql.DB, table string) map[string][]string {
	t.Helper()
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name=?", table)
	if err != nil {
		t.Fatalf("list indexes on %s: %v", table, err)
	}
	names := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan index name: %v", err)
		}
		names = append(names, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("index rows: %v", err)
	}
	out := map[string][]string{}
	for _, name := range names {
		ci, err := db.Query("PRAGMA index_info(" + name + ")")
		if err != nil {
			t.Fatalf("index_info %s: %v", name, err)
		}
		cols := []string{}
		for ci.Next() {
			var seq, cid int
			var col string
			if err := ci.Scan(&seq, &cid, &col); err != nil {
				t.Fatalf("scan index_info %s: %v", name, err)
			}
			cols = append(cols, col)
		}
		ci.Close()
		if err := ci.Err(); err != nil {
			t.Fatalf("index_info rows %s: %v", name, err)
		}
		out[name] = cols
	}
	return out
}

// assertV2Schema pins the schema a fresh database and a migrated v1 database
// must share: user_version 2, the old three-column index gone, and
// api_keys_email_fingerprint on (email, fingerprint) in its place.
func assertV2Schema(t *testing.T, db *sql.DB) {
	t.Helper()
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("user_version: %v", err)
	}
	if version != 2 {
		t.Fatalf("user_version = %d, want 2", version)
	}
	idx := indexColumns(t, db, "api_keys")
	if _, ok := idx["api_keys_email_provider_fingerprint"]; ok {
		t.Fatalf("old index api_keys_email_provider_fingerprint still present: %+v", idx)
	}
	cols, ok := idx["api_keys_email_fingerprint"]
	if !ok {
		t.Fatalf("index api_keys_email_fingerprint missing: %+v", idx)
	}
	want := []string{"email", "fingerprint"}
	if len(cols) != len(want) {
		t.Fatalf("index columns = %v, want %v", cols, want)
	}
	for i := range want {
		if cols[i] != want[i] {
			t.Fatalf("index columns = %v, want %v", cols, want)
		}
	}
}

func TestFreshDBHasEmailFingerprintIndex(t *testing.T) {
	db, err := Open(openTemp(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	assertV2Schema(t, db)
}

// TestV1DatabaseMigratesToV2 builds a database exactly as the v1 migration
// left it (user_version 1, the old three-column index, rows present), then
// reopens it through Open. It must end with the same schema as a fresh
// database and keep its rows.
func TestV1DatabaseMigratesToV2(t *testing.T) {
	path := openTemp(t)
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if _, err := db.Exec(migrations[0]); err != nil {
		t.Fatalf("apply v1 schema: %v", err)
	}
	if _, err := db.Exec("PRAGMA user_version = 1"); err != nil {
		t.Fatalf("set user_version: %v", err)
	}
	res, err := db.Exec("INSERT INTO providers (name) VALUES ('Gemini')")
	if err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	pid, _ := res.LastInsertId()
	if _, err := db.Exec("INSERT INTO api_keys (email, provider_id, encrypted_key, nonce, fingerprint) VALUES ('a@b.c', ?, x'01', x'02', x'03')", pid); err != nil {
		t.Fatalf("insert key: %v", err)
	}
	db.Close()

	db2, err := Open(path)
	if err != nil {
		t.Fatalf("Open v1 database: %v", err)
	}
	defer db2.Close()
	assertV2Schema(t, db2)

	var email string
	var fpr []byte
	if err := db2.QueryRow("SELECT email, fingerprint FROM api_keys WHERE provider_id = ?", pid).Scan(&email, &fpr); err != nil {
		t.Fatalf("row did not survive migration: %v", err)
	}
	if email != "a@b.c" || len(fpr) != 1 || fpr[0] != 0x03 {
		t.Fatalf("row = (%q, %x), want (a@b.c, 03)", email, fpr)
	}
}
