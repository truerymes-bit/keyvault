package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"keyvault/internal/encryption"
	"keyvault/internal/security"
)

type KeysHandler struct {
	DB   *sql.DB
	Auth *security.Auth
}

const maskedKey = "••••••••"

var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

type keyJSON struct {
	ID                int64  `json:"id"`
	Email             string `json:"email"`
	ProviderID        int64  `json:"provider_id"`
	ProviderName      string `json:"provider_name"`
	Label             string `json:"label"`
	Key               string `json:"key"`
	FingerprintPrefix string `json:"fingerprint_prefix"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

type keyRequest struct {
	Email      string `json:"email"`
	ProviderID int64  `json:"provider_id"`
	Label      string `json:"label"`
	Key        string `json:"key"`
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

func keyID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid key id")
		return 0, false
	}
	return id, true
}

func fingerprint(hmacSubkey, plaintext []byte) []byte {
	h := hmac.New(sha256.New, hmacSubkey)
	h.Write(plaintext)
	return h.Sum(nil)
}

func scanKey(row interface{ Scan(...any) error }) (keyJSON, error) {
	var k keyJSON
	var fp []byte
	var created, updated time.Time
	err := row.Scan(&k.ID, &k.Email, &k.ProviderID, &k.ProviderName, &k.Label, &fp, &created, &updated)
	k.Key = maskedKey
	if len(fp) >= 4 {
		k.FingerprintPrefix = hex.EncodeToString(fp[:4])
	}
	k.CreatedAt = created.UTC().Format(time.RFC3339)
	k.UpdatedAt = updated.UTC().Format(time.RFC3339)
	return k, err
}

const keySelect = `
SELECT k.id, k.email, k.provider_id, p.name, k.label, k.fingerprint, k.created_at, k.updated_at
FROM api_keys k JOIN providers p ON p.id = k.provider_id`

func (h *KeysHandler) subkeys(w http.ResponseWriter) *encryption.Subkeys {
	sk := h.Auth.Subkeys()
	if sk == nil {
		writeErr(w, http.StatusLocked, "locked")
		return nil
	}
	return sk
}

// List handles GET /api/keys. Never returns plaintext. Optional ?q= filters
// by substring against email, provider name and label (case-insensitive).
func (h *KeysHandler) List(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	sqlStr := keySelect
	var args []any
	if query != "" {
		like := "%" + escapeLike(strings.ToLower(query)) + "%"
		sqlStr += ` WHERE lower(k.email) LIKE ? ESCAPE '\' OR lower(p.name) LIKE ? ESCAPE '\' OR lower(k.label) LIKE ? ESCAPE '\'`
		args = append(args, like, like, like)
	}
	sqlStr += " ORDER BY k.email COLLATE NOCASE, p.name COLLATE NOCASE, k.id"
	rows, err := h.DB.Query(sqlStr, args...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()
	out := []keyJSON{}
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		out = append(out, k)
	}
	writeJSON(w, http.StatusOK, out)
}

// Get handles GET /api/keys/{id}. Masked.
func (h *KeysHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := keyID(w, r)
	if !ok {
		return
	}
	k, err := scanKey(h.DB.QueryRow(keySelect+" WHERE k.id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "key not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, k)
}

func validKeyInput(email string, providerID int64) string {
	email = strings.TrimSpace(email)
	if !emailRe.MatchString(email) {
		return "invalid email address"
	}
	if providerID <= 0 {
		return "provider_id must be a positive integer"
	}
	return ""
}

func (h *KeysHandler) providerExists(id int64) (bool, error) {
	var n int
	err := h.DB.QueryRow("SELECT count(*) FROM providers WHERE id = ?", id).Scan(&n)
	return n > 0, err
}

// Create handles POST /api/keys.
func (h *KeysHandler) Create(w http.ResponseWriter, r *http.Request) {
	sk := h.subkeys(w)
	if sk == nil {
		return
	}
	var req keyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if msg := validKeyInput(req.Email, req.ProviderID); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	if strings.TrimSpace(req.Key) == "" {
		writeErr(w, http.StatusBadRequest, "key must not be empty")
		return
	}
	exists, err := h.providerExists(req.ProviderID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !exists {
		writeErr(w, http.StatusBadRequest, "provider does not exist")
		return
	}

	ct, nonce, err := encryption.Seal(sk.Enc, []byte(req.Key))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	fp := fingerprint(sk.HMAC, []byte(req.Key))
	res, err := h.DB.Exec(
		"INSERT INTO api_keys (email, provider_id, label, encrypted_key, nonce, fingerprint) VALUES (?, ?, ?, ?, ?, ?)",
		req.Email, req.ProviderID, strings.TrimSpace(req.Label), ct, nonce, fp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	id, _ := res.LastInsertId()
	k, err := scanKey(h.DB.QueryRow(keySelect+" WHERE k.id = ?", id))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, k)
}

// Update handles PUT /api/keys/{id}. The key field is optional; when present
// the key is re-encrypted and re-fingerprinted.
func (h *KeysHandler) Update(w http.ResponseWriter, r *http.Request) {
	sk := h.subkeys(w)
	if sk == nil {
		return
	}
	id, ok := keyID(w, r)
	if !ok {
		return
	}
	var req keyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	var cur struct {
		email      string
		providerID int64
		label      string
	}
	err := h.DB.QueryRow("SELECT email, provider_id, label FROM api_keys WHERE id = ?", id).
		Scan(&cur.email, &cur.providerID, &cur.label)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "key not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if e := strings.TrimSpace(req.Email); e != "" {
		cur.email = e
	}
	if req.ProviderID != 0 {
		cur.providerID = req.ProviderID
	}
	if req.Label != "" {
		cur.label = strings.TrimSpace(req.Label)
	}
	if msg := validKeyInput(cur.email, cur.providerID); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	exists, err := h.providerExists(cur.providerID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !exists {
		writeErr(w, http.StatusBadRequest, "provider does not exist")
		return
	}

	if strings.TrimSpace(req.Key) != "" {
		ct, nonce, err := encryption.Seal(sk.Enc, []byte(req.Key))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		fp := fingerprint(sk.HMAC, []byte(req.Key))
		_, err = h.DB.Exec(
			"UPDATE api_keys SET email = ?, provider_id = ?, label = ?, encrypted_key = ?, nonce = ?, fingerprint = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
			cur.email, cur.providerID, cur.label, ct, nonce, fp, id)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
	} else {
		_, err = h.DB.Exec(
			"UPDATE api_keys SET email = ?, provider_id = ?, label = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
			cur.email, cur.providerID, cur.label, id)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
	k, err := scanKey(h.DB.QueryRow(keySelect+" WHERE k.id = ?", id))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, k)
}

// Delete handles DELETE /api/keys/{id}.
func (h *KeysHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, ok := keyID(w, r)
	if !ok {
		return
	}
	res, err := h.DB.Exec("DELETE FROM api_keys WHERE id = ?", id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, http.StatusNotFound, "key not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Reveal handles POST /api/keys/{id}/reveal. Returns the plaintext key;
// the client is expected to display it briefly.
func (h *KeysHandler) Reveal(w http.ResponseWriter, r *http.Request) {
	sk := h.subkeys(w)
	if sk == nil {
		return
	}
	id, ok := keyID(w, r)
	if !ok {
		return
	}
	var ct, nonce []byte
	err := h.DB.QueryRow("SELECT encrypted_key, nonce FROM api_keys WHERE id = ?", id).Scan(&ct, &nonce)
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "key not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	plaintext, err := encryption.Open(sk.Enc, ct, nonce)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"key": string(plaintext)})
}
