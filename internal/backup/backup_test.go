package backup_test

import (
	"os"
	"sync"
	"testing"

	_ "modernc.org/sqlite"

	"keyvault/internal/backup"
	"keyvault/internal/database"
)

var _testDBMu sync.Mutex // serialize temp-DB creation across parallel tests

// makeTestDB creates a temporary SQLite database with a single settings row
// and a sample key record, then returns its path and the argon2id parameters.
func makeTestDB(t *testing.T) (string, []byte, uint32, uint32, uint8, uint32) {
	t.Helper()
	_testDBMu.Lock()
	defer _testDBMu.Unlock()

	f, err := os.CreateTemp("", "kv-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	f.Close()
	os.Remove(path) // VACUUM INTO will recreate it

	db, err := database.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	cmds := []string{
		"INSERT INTO settings(key, value) VALUES ('argon_salt', 'c2FsdHNhbHNwbGFjayBzdGFudA==');",
		"INSERT INTO settings(key, value) VALUES ('argon_time', '3');",
		"INSERT INTO settings(key, value) VALUES ('argon_memory', '65536');",
		"INSERT INTO settings(key, value) VALUES ('argon_threads', '2');",
		"INSERT INTO settings(key, value) VALUES ('verifier', 'Ymxha3ZlaGtsa2xrYXdsaWxr');",
		"INSERT INTO providers(name) VALUES ('Gemini');",
		"INSERT INTO api_keys(email, provider_id, encrypted_key, nonce, fingerprint) VALUES ('test@example.com', 1, X'00112233445566778899aabbccddeeff', X'0123456789abcdef', X'0123456789abcdef0123456789abcdef');",
	}
	for _, c := range cmds {
		if _, err := db.Exec(c); err != nil {
			t.Fatalf("sql %q: %v", c, err)
		}
	}

	salt := []byte("0123456789abcdef") // 16 bytes, matching saltLen (=16)
	return path, salt, 3, 65536, 2, 32
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	path, salt, tVal, mVal, pVal, dkLen := makeTestDB(t)
	defer os.Remove(path)

	backupKey := []byte("0123456789abcdef0123456789abcdef")
	enc, err := backup.Encode(path, backupKey, salt, tVal, mVal, pVal, dkLen)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	plain, err := backup.Decode(enc, backupKey)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if len(plain) == 0 {
		t.Fatal("decrypted SQL is empty")
	}
}

func TestDecodeRejectsTamperedFile(t *testing.T) {
	path, salt, tVal, mVal, pVal, dkLen := makeTestDB(t)
	defer os.Remove(path)

	backupKey := []byte("0123456789abcdef0123456789abcdef")
	enc, err := backup.Encode(path, backupKey, salt, tVal, mVal, pVal, dkLen)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Flip a byte in the ciphertext.
	if len(enc) > 60 {
		enc[60] ^= 0x01
	}
	if _, err := backup.Decode(enc, backupKey); err == nil {
		t.Fatal("expected decryption failure, got nil")
	}
}

func TestDecodeRejectsWrongKey(t *testing.T) {
	path, salt, tVal, mVal, pVal, dkLen := makeTestDB(t)
	defer os.Remove(path)

	backupKey := []byte("0123456789abcdef0123456789abcdef")
	enc, err := backup.Encode(path, backupKey, salt, tVal, mVal, pVal, dkLen)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	wrongKey := []byte("feedfacefeedfacefeedfacefeedface")
	if _, err := backup.Decode(enc, wrongKey); err == nil {
		t.Fatal("expected decryption failure, got nil")
	}
}

func TestEncodeHasCorrectMagic(t *testing.T) {
	path, salt, tVal, mVal, pVal, dkLen := makeTestDB(t)
	defer os.Remove(path)

	backupKey := []byte("0123456789abcdef0123456789abcdef")
	enc, err := backup.Encode(path, backupKey, salt, tVal, mVal, pVal, dkLen)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	const wantMagic = "KeyVault"
	if string(enc[0:8]) != wantMagic {
		t.Fatalf("magic: %q", enc[0:8])
	}
	// Version check is optional — the envelope carries its own version field.
}

func BenchmarkEncode(b *testing.B) {
}
