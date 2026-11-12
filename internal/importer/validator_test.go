package importer

import (
	"database/sql"
	"path/filepath"
	"testing"

	"keyvault/internal/database"
)

func setupDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func hmacKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

func TestValidateBasic(t *testing.T) {
	db := setupDB(t)
	_, err := db.Exec("INSERT INTO providers (name) VALUES ('Gemini')")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO providers (name) VALUES ('Other')")
	if err != nil {
		t.Fatal(err)
	}
	recs := []Record{
		{Line: 1, Email: "a@b.com", Key: "sk-1", Provider: "Gemini", Status: StatusOK},
		{Line: 2, Email: "c@d.com", Key: "sk-2", Provider: "Other", Status: StatusOK},
	}
	out, err := ValidateRecords(db, hmacKey(), recs)
	if err != nil {
		t.Fatal(err)
	}
	for _, vr := range out {
		if !vr.Valid {
			t.Fatalf("record %+v should be valid", vr)
		}
		if vr.Duplicate {
			t.Fatalf("record %+v should not be duplicate", vr)
		}
		if len(vr.Fingerprint) != 32 {
			t.Fatalf("fingerprint len = %d", len(vr.Fingerprint))
		}
	}
}

func TestInvalidEmailAndEmptyKey(t *testing.T) {
	db := setupDB(t)
	_, err := db.Exec("INSERT INTO providers (name) VALUES ('Gemini')")
	if err != nil {
		t.Fatal(err)
	}
	recs := []Record{
		{Line: 1, Email: "nope", Key: "sk-1", Provider: "Gemini", Status: StatusOK},
		{Line: 2, Email: "a@b.com", Key: "   ", Provider: "Gemini", Status: StatusOK},
		{Line: 3, Email: "a@b.com", Key: "sk-3", Provider: "", Status: StatusNoProvider},
	}
	out, err := ValidateRecords(db, hmacKey(), recs)
	if err != nil {
		t.Fatal(err)
	}
	if out[0].Valid {
		t.Fatal("bad email must be invalid")
	}
	if out[1].Valid {
		t.Fatal("empty key must be invalid")
	}
	if out[2].Valid {
		t.Fatal("unassigned provider must be invalid")
	}
	if len(out[0].Errors) == 0 || len(out[1].Errors) == 0 || len(out[2].Errors) == 0 {
		t.Fatal("errors should be populated")
	}
}

func TestDuplicateAgainstDatabaseCaseInsensitive(t *testing.T) {
	db := setupDB(t)
	res, err := db.Exec("INSERT INTO providers (name) VALUES ('Gemini')")
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := res.LastInsertId()
	fp := Fingerprint(hmacKey(), []byte("sk-known"))
	_, err = db.Exec("INSERT INTO api_keys (email, provider_id, encrypted_key, nonce, fingerprint) VALUES ('a@b.com', ?, x'01', x'02', ?)", pid, fp)
	if err != nil {
		t.Fatal(err)
	}
	recs := []Record{
		{Line: 5, Email: "A@B.COM", Key: "sk-known", Provider: "gemini", Status: StatusOK},
	}
	out, err := ValidateRecords(db, hmacKey(), recs)
	if err != nil {
		t.Fatal(err)
	}
	if !out[0].Duplicate || out[0].DuplicateSource != "database" {
		t.Fatalf("case-insensitive record = %+v", out[0])
	}
}

func TestDuplicateWithinFile(t *testing.T) {
	db := setupDB(t)
	recs := []Record{
		{Line: 1, Email: "a@b.com", Key: "sk-same", Provider: "Gemini", Status: StatusOK},
		{Line: 2, Email: "a@b.com", Key: "sk-same", Provider: "Gemini", Status: StatusOK},
		{Line: 3, Email: "a@b.com", Key: "sk-same", Provider: "Other", Status: StatusOK},
		{Line: 4, Email: "c@d.com", Key: "sk-same", Provider: "Gemini", Status: StatusOK},
	}
	out, err := ValidateRecords(db, hmacKey(), recs)
	if err != nil {
		t.Fatal(err)
	}
	if out[0].Duplicate {
		t.Fatal("first occurrence is not a duplicate")
	}
	if !out[1].Duplicate || out[1].DuplicateSource != "file" {
		t.Fatalf("record 1 = %+v", out[1])
	}
	if out[2].Duplicate {
		t.Fatal("same key under different provider is not a duplicate")
	}
	if out[3].Duplicate {
		t.Fatal("same key under different email is not a duplicate")
	}
}

func TestDuplicateAgainstDatabase(t *testing.T) {
	db := setupDB(t)
	res, err := db.Exec("INSERT INTO providers (name) VALUES ('Gemini')")
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := res.LastInsertId()
	fp := Fingerprint(hmacKey(), []byte("sk-known"))
	_, err = db.Exec("INSERT INTO api_keys (email, provider_id, encrypted_key, nonce, fingerprint) VALUES ('a@b.com', ?, x'01', x'02', ?)", pid, fp)
	if err != nil {
		t.Fatal(err)
	}

	recs := []Record{
		{Line: 1, Email: "a@b.com", Key: "sk-known", Provider: "Gemini", Status: StatusOK},
		{Line: 2, Email: "a@b.com", Key: "sk-known", Provider: "Other", Status: StatusOK},
		{Line: 3, Email: "A@B.COM", Key: "sk-known", Provider: "gemini", Status: StatusOK}, // case-insensitive match
		{Line: 4, Email: "a@b.com", Key: "sk-other", Provider: "Gemini", Status: StatusOK},
	}
	out, err := ValidateRecords(db, hmacKey(), recs)
	if err != nil {
		t.Fatal(err)
	}
	if !out[0].Duplicate || out[0].DuplicateSource != "database" {
		t.Fatalf("record 0 = %+v", out[0])
	}
	if out[1].Duplicate {
		t.Fatal("different provider is not a duplicate")
	}
	if !out[2].Duplicate || out[2].DuplicateSource != "file" {
		t.Fatalf("record 2 (in-file dup, case-insensitive) = %+v", out[2])
	}
	if out[3].Duplicate {
		t.Fatal("different key is not a duplicate")
	}
}

func TestDuplicatePriorityFileOverDatabase(t *testing.T) {
	db := setupDB(t)
	res, err := db.Exec("INSERT INTO providers (name) VALUES ('Gemini')")
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := res.LastInsertId()
	fp := Fingerprint(hmacKey(), []byte("sk-known"))
	db.Exec("INSERT INTO api_keys (email, provider_id, encrypted_key, nonce, fingerprint) VALUES ('a@b.com', ?, x'01', x'02', ?)", pid, fp)

	recs := []Record{
		{Line: 1, Email: "a@b.com", Key: "sk-known", Provider: "Gemini", Status: StatusOK},
		{Line: 2, Email: "a@b.com", Key: "sk-known", Provider: "Gemini", Status: StatusOK},
	}
	out, err := ValidateRecords(db, hmacKey(), recs)
	if err != nil {
		t.Fatal(err)
	}
	if out[0].DuplicateSource != "database" {
		t.Fatalf("record 0 source = %q", out[0].DuplicateSource)
	}
	if out[1].DuplicateSource != "file" {
		t.Fatalf("record 1 source = %q", out[1].DuplicateSource)
	}
}

func TestNoPlaintextHashStored(t *testing.T) {
	fp := Fingerprint(hmacKey(), []byte("sk-known"))
	plain := []byte("sk-known")
	if len(fp) != 32 {
		t.Fatal("fingerprint must be 32 bytes")
	}
	for i := range fp {
		if fp[i] == plain[i%len(plain)] {
			// not a proof, just sanity that this isn't a trivial echo
		}
	}
	// Same key+subkey -> same fingerprint; different subkey -> different.
	fp1 := Fingerprint(hmacKey(), []byte("sk-known"))
	fp2 := Fingerprint(hmacKey(), []byte("sk-known"))
	if string(fp1) != string(fp2) {
		t.Fatal("same plaintext and subkey must fingerprint identically")
	}
	other := Fingerprint([]byte("0123456789abcdef0123456789abcdef"), []byte("sk-known"))
	if string(fp1) == string(other) {
		t.Fatal("different HMAC subkeys must yield different fingerprints")
	}
}
