package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type ProvidersHandler struct {
	DB *sql.DB
}

type providerJSON struct {
	ID        int64    `json:"id"`
	Name      string   `json:"name"`
	Notes     string   `json:"notes"`
	KeyCount  int      `json:"key_count"`
	Emails    []string `json:"emails,omitempty"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
}

type providerRequest struct {
	Name string `json:"name"`
}

type notesRequest struct {
	Notes string `json:"notes"`
}

func providerID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid provider id")
		return 0, false
	}
	return id, true
}

func scanProvider(row interface{ Scan(...any) error }) (providerJSON, error) {
	var p providerJSON
	var created, updated time.Time
	err := row.Scan(&p.ID, &p.Name, &p.Notes, &p.KeyCount, &created, &updated)
	p.CreatedAt = created.UTC().Format(time.RFC3339)
	p.UpdatedAt = updated.UTC().Format(time.RFC3339)
	return p, err
}

const providerSelect = `
SELECT p.id, p.name, p.notes,
       (SELECT count(*) FROM api_keys k WHERE k.provider_id = p.id) AS key_count,
       p.created_at, p.updated_at
FROM providers p`

// List handles GET /api/providers.
func (h *ProvidersHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Query(providerSelect + " ORDER BY p.name COLLATE NOCASE")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()
	out := []providerJSON{}
	for rows.Next() {
		p, err := scanProvider(rows)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		out = append(out, p)
	}
	writeJSON(w, http.StatusOK, out)
}

// Get handles GET /api/providers/{id}.
func (h *ProvidersHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := providerID(w, r)
	if !ok {
		return
	}
	p, err := scanProvider(h.DB.QueryRow(providerSelect+" WHERE p.id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusNotFound, "provider not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	rows, err := h.DB.Query("SELECT DISTINCT email FROM api_keys WHERE provider_id = ? ORDER BY email", id)
	if err == nil {
		defer rows.Close()
		p.Emails = []string{}
		for rows.Next() {
			var e string
			if err := rows.Scan(&e); err == nil {
				p.Emails = append(p.Emails, e)
			}
		}
	}
	writeJSON(w, http.StatusOK, p)
}

// Create handles POST /api/providers.
func (h *ProvidersHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req providerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeErr(w, http.StatusBadRequest, "name must not be empty")
		return
	}
	res, err := h.DB.Exec("INSERT INTO providers (name) VALUES (?)", name)
	if err != nil {
		if isUniqueViolation(err) {
			writeErr(w, http.StatusConflict, "provider already exists")
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	id, _ := res.LastInsertId()
	p, err := scanProvider(h.DB.QueryRow(providerSelect+" WHERE p.id = ?", id))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

// Update handles PUT /api/providers/{id}.
func (h *ProvidersHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, ok := providerID(w, r)
	if !ok {
		return
	}
	var req providerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeErr(w, http.StatusBadRequest, "name must not be empty")
		return
	}
	res, err := h.DB.Exec("UPDATE providers SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", name, id)
	if err != nil {
		if isUniqueViolation(err) {
			writeErr(w, http.StatusConflict, "provider already exists")
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, http.StatusNotFound, "provider not found")
		return
	}
	p, err := scanProvider(h.DB.QueryRow(providerSelect+" WHERE p.id = ?", id))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// Delete handles DELETE /api/providers/{id}. Returns 409 with the key count
// when keys still reference the provider.
func (h *ProvidersHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, ok := providerID(w, r)
	if !ok {
		return
	}
	var keyCount int
	if err := h.DB.QueryRow("SELECT count(*) FROM api_keys WHERE provider_id = ?", id).Scan(&keyCount); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if keyCount > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":     "provider has keys; reassign or delete them first",
			"key_count": keyCount,
		})
		return
	}
	res, err := h.DB.Exec("DELETE FROM providers WHERE id = ?", id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, http.StatusNotFound, "provider not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// UpdateNotes handles PUT /api/providers/{id}/notes.
func (h *ProvidersHandler) UpdateNotes(w http.ResponseWriter, r *http.Request) {
	id, ok := providerID(w, r)
	if !ok {
		return
	}
	var req notesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	res, err := h.DB.Exec("UPDATE providers SET notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", req.Notes, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, http.StatusNotFound, "provider not found")
		return
	}
	p, err := scanProvider(h.DB.QueryRow(providerSelect+" WHERE p.id = ?", id))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique")
}
