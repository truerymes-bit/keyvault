package handlers

import (
	"bytes"
	"database/sql"
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

type keysTestEnv struct {
	t      *testing.T
	mux    *http.ServeMux
	db     *sql.DB
	cookie *http.Cookie
	csrf   string
	provID int64
}

func newKeysEnv(t *testing.T) *keysTestEnv {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	res, err := db.Exec("INSERT INTO providers (name) VALUES ('Gemini')")
	if err != nil {
		t.Fatal(err)
	}
	provID, _ := res.LastInsertId()

	auth := security.NewAuth(db)
	if err := auth.Setup("hunter2"); err != nil {
		t.Fatal(err)
	}
	sm := security.NewSessionManager(auth, 15*time.Minute)
	h := &KeysHandler{DB: db, Auth: auth}
	protected := func(fn http.HandlerFunc) http.Handler {
		return RequireSession(sm, fn)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /api/keys", protected(h.List))
	mux.Handle("GET /api/keys/{id}", protected(h.Get))
	mux.Handle("POST /api/keys", protected(h.Create))
	mux.Handle("PUT /api/keys/{id}", protected(h.Update))
	mux.Handle("DELETE /api/keys/{id}", protected(h.Delete))

	rec := httptest.NewRecorder()
	s, err := sm.Create(rec)
	if err != nil {
		t.Fatal(err)
	}
	return &keysTestEnv{
		t:      t,
		mux:    mux,
		db:     db,
		cookie: rec.Result().Cookies()[0],
		csrf:   s.CSRF,
		provID: provID,
	}
}

func (e *keysTestEnv) do(method, path, body string, withCSRF bool) *httptest.ResponseRecorder {
	e.t.Helper()
	req := httptest.NewRequest(method, "http://x"+path, strings.NewReader(body))
	req.AddCookie(e.cookie)
	if withCSRF {
		req.Header.Set(security.CSRFHeader, e.csrf)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func (e *keysTestEnv) createKey(email, label, key string) *httptest.ResponseRecorder {
	body := fmt.Sprintf(`{"email":%q,"provider_id":%d,"label":%q,"key":%q}`, email, e.provID, label, key)
	return e.do(http.MethodPost, "/api/keys", body, true)
}

func TestCreateAndListNeverLeakPlaintext(t *testing.T) {
	e := newKeysEnv(t)
	plaintext := "sk-secret-1234567890abcdef"
	rec := e.createKey("a@b.com", "main", plaintext)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}

	// Raw DB must not contain the plaintext.
	var ct, nonce []byte
	if err := e.db.QueryRow("SELECT encrypted_key, nonce FROM api_keys").Scan(&ct, &nonce); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte(plaintext)) {
		t.Fatal("encrypted_key contains plaintext")
	}

	for _, path := range []string{"/api/keys", "/api/keys/1"} {
		rec := e.do(http.MethodGet, path, "", false)
		if strings.Contains(rec.Body.String(), plaintext) {
			t.Fatalf("%s leaks plaintext: %s", path, rec.Body)
		}
		if !strings.Contains(rec.Body.String(), maskedKey) {
			t.Fatalf("%s missing masked key: %s", path, rec.Body)
		}
	}
}

func TestEmailValidationRejected(t *testing.T) {
	e := newKeysEnv(t)
	for _, bad := range []string{"", "notanemail", "a@b", "a b@c.com"} {
		rec := e.createKey(bad, "", "sk-x")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("email %q: %d, want 400", bad, rec.Code)
		}
	}
}

func TestEmptyKeyRejected(t *testing.T) {
	e := newKeysEnv(t)
	rec := e.createKey("a@b.com", "", "   ")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty key: %d, want 400", rec.Code)
	}
}

func TestNonexistentProviderRejected(t *testing.T) {
	e := newKeysEnv(t)
	rec := e.do(http.MethodPost, "/api/keys", `{"email":"a@b.com","provider_id":9999,"key":"sk-x"}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("provider: %d, want 400", rec.Code)
	}
}

func TestMultipleKeysPerEmailProviderAllowed(t *testing.T) {
	e := newKeysEnv(t)
	for i := 0; i < 3; i++ {
		rec := e.createKey("a@b.com", fmt.Sprintf("k%d", i), fmt.Sprintf("sk-%d", i))
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	rec := e.do(http.MethodGet, "/api/keys", "", false)
	var list []keyJSON
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 3 {
		t.Fatalf("list len = %d, want 3", len(list))
	}
}

func TestFingerprintDeterministic(t *testing.T) {
	e := newKeysEnv(t)
	e.createKey("a@b.com", "one", "sk-same")
	e.createKey("c@d.com", "two", "sk-same")
	rows, err := e.db.Query("SELECT fingerprint FROM api_keys ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var fps [][]byte
	for rows.Next() {
		var fp []byte
		_ = rows.Scan(&fp)
		fps = append(fps, fp)
	}
	if len(fps) != 2 || !bytes.Equal(fps[0], fps[1]) {
		t.Fatal("same plaintext must produce the same fingerprint")
	}
}

func TestUpdateReencryptsKey(t *testing.T) {
	e := newKeysEnv(t)
	e.createKey("a@b.com", "old", "sk-old-plain")
	var ct1 []byte
	_ = e.db.QueryRow("SELECT encrypted_key FROM api_keys WHERE id = 1").Scan(&ct1)

	rec := e.do(http.MethodPut, "/api/keys/1", `{"key":"sk-new-plain","label":"new"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	var ct2 []byte
	_ = e.db.QueryRow("SELECT encrypted_key FROM api_keys WHERE id = 1").Scan(&ct2)
	if bytes.Equal(ct1, ct2) {
		t.Fatal("ciphertext did not change after key update")
	}
	var label string
	_ = e.db.QueryRow("SELECT label FROM api_keys WHERE id = 1").Scan(&label)
	if label != "new" {
		t.Fatalf("label = %q", label)
	}

	// Update without key field leaves the key alone.
	rec = e.do(http.MethodPut, "/api/keys/1", `{"label":"newer"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("label update: %d", rec.Code)
	}
	var ct3 []byte
	_ = e.db.QueryRow("SELECT encrypted_key FROM api_keys WHERE id = 1").Scan(&ct3)
	if !bytes.Equal(ct2, ct3) {
		t.Fatal("key ciphertext changed on metadata-only update")
	}
}

func TestDeleteKey(t *testing.T) {
	e := newKeysEnv(t)
	e.createKey("a@b.com", "x", "sk-x")
	rec := e.do(http.MethodDelete, "/api/keys/1", "", true)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	rec = e.do(http.MethodDelete, "/api/keys/1", "", true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("re-delete: %d, want 404", rec.Code)
	}
}
