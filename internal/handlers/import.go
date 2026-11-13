package handlers

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"keyvault/internal/encryption"
	"keyvault/internal/importer"
	"keyvault/internal/security"
)

type ImportHandler struct {
	DB       *sql.DB
	Auth     *security.Auth
	Sessions *importer.SessionStore
}

// importRowJSON is the wire shape of one validated row. The key is never
// echoed; the client replaces it wholesale when the user edits it.
type importRowJSON struct {
	Index             int      `json:"index"`
	Line              int      `json:"line"`
	Email             string   `json:"email"`
	Provider          string   `json:"provider"`
	Key               string   `json:"key"`
	FingerprintPrefix string   `json:"fingerprint_prefix,omitempty"`
	Status            string   `json:"status"`
	Valid             bool     `json:"valid"`
	Errors            []string `json:"errors,omitempty"`
	Duplicate         bool     `json:"duplicate"`
	DuplicateSource   string   `json:"duplicate_source,omitempty"`
}

type importUnmatchedJSON struct {
	Line   int    `json:"line"`
	Text   string `json:"text"`
	Reason string `json:"reason"`
}

type parseRequest struct {
	Text            string   `json:"text"`
	Format          string   `json:"format"` // "txt" or "csv"
	CustomProviders []string `json:"custom_providers,omitempty"`
}

// importRowEdit is a full replacement edit for one row. Any non-empty Email,
// Provider, Label or Key field replaces the stored value; the key is never
// echoed in responses, so editing it means retyping it.
type importRowEdit struct {
	Index    int    `json:"index"`
	Email    string `json:"email,omitempty"`
	Provider string `json:"provider,omitempty"`
	Key      string `json:"key,omitempty"`
}

type editRequest struct {
	SessionID string          `json:"session_id"`
	Records   []importRowEdit `json:"records,omitempty"`
}

type commitRequest struct {
	SessionID     string          `json:"session_id"`
	Records       []importRowEdit `json:"records,omitempty"`
	DuplicateMode string          `json:"duplicate_mode"` // skip, import, review
}

var unmatchedEmailRe = regexp.MustCompile(`^([^\s@]+@[^\s@]+\.[^\s@]+)\s+(\S.*)$`)

func maskUnmatched(text string) string {
	if m := unmatchedEmailRe.FindStringSubmatch(text); m != nil {
		rest := m[2]
		fields := strings.Fields(rest)
		if len(fields) >= 1 {
			return m[1] + " " + maskedKey
		}
		return m[1] + " " + maskedKey
	}
	// A bare line could itself be a key; never echo it.
	return maskedKey
}

func rowsJSON(recs []importer.ValidatedRecord) []importRowJSON {
	out := make([]importRowJSON, 0, len(recs))
	for i, r := range recs {
		row := importRowJSON{
			Index:           i,
			Line:            r.Line,
			Email:           r.Email,
			Provider:        r.Provider,
			Key:             maskedKey,
			Status:          r.Status,
			Valid:           r.Valid,
			Errors:          r.Errors,
			Duplicate:       r.Duplicate,
			DuplicateSource: r.DuplicateSource,
		}
		if len(r.Fingerprint) >= 4 {
			row.FingerprintPrefix = hex.EncodeToString(r.Fingerprint[:4])
		}
		out = append(out, row)
	}
	return out
}

// newProvidersJSON serializes new provider candidates for the import
// preview. Keys are masked; a new provider contains the grouped records
// under it for the user to confirm with one click.
func newProvidersJSON(nps []*importer.NewProvider) []any {
	out := make([]any, len(nps))
	for i, np := range nps {
		records := make([]any, len(np.Records))
		for j, r := range np.Records {
			records[j] = map[string]any{
				"index":    i*10000 + j,
				"line":     r.Line,
				"email":    r.Email,
				"provider": r.Provider,
				"key":      maskedKey,
				"status":   r.Status,
				"valid":    true,
			}
		}
		out[i] = map[string]any{
			"name":    np.Name,
			"records": records,
		}
	}
	return out
}

func unmatchedJSON(lines []importer.UnmatchedLine) []importUnmatchedJSON {
	out := make([]importUnmatchedJSON, 0, len(lines))
	for _, u := range lines {
		out = append(out, importUnmatchedJSON{Line: u.Line, Text: maskUnmatched(u.Text), Reason: u.Reason})
	}
	return out
}

// applyEdits returns a new record slice with the given replacements applied.
// Edits are full replacement values; an index out of range is rejected.
func applyEdits(records []importer.Record, edits []importRowEdit) ([]importer.Record, error) {
	out := make([]importer.Record, len(records))
	copy(out, records)
	for _, e := range edits {
		if e.Index < 0 || e.Index >= len(out) {
			return nil, fmt.Errorf("record index %d out of range", e.Index)
		}
		r := &out[e.Index]
		if v := strings.TrimSpace(e.Email); v != "" {
			r.Email = v
		}
		if v := strings.TrimSpace(e.Provider); v != "" {
			r.Provider = v
			r.Status = importer.StatusOK
		}
		if v := strings.TrimSpace(e.Key); v != "" {
			r.Key = v
		}
	}
	return out, nil
}

func validate(h *ImportHandler, w http.ResponseWriter, records []importer.Record) ([]importer.ValidatedRecord, bool) {
	sk := h.Auth.Subkeys()
	if sk == nil {
		writeErr(w, http.StatusLocked, "locked")
		return nil, false
	}
	out, err := importer.ValidateRecords(h.DB, sk.HMAC, records)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return nil, false
	}
	return out, true
}

func parseBody(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 4<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// Parse handles POST /api/import/parse. It creates an import session; the
// parsed rows live in memory on the server.
func (h *ImportHandler) Parse(w http.ResponseWriter, r *http.Request) {
	if h.Auth.Subkeys() == nil {
		writeErr(w, http.StatusLocked, "locked")
		return
	}
	var req parseRequest
	if err := parseBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Text = strings.TrimSpace(req.Text)
	if req.Text == "" {
		writeErr(w, http.StatusBadRequest, "text must not be empty")
		return
	}
	var res *importer.Result
	var err error
	switch strings.ToLower(strings.TrimSpace(req.Format)) {
	case "txt":
		res = importer.ParseTXT(req.Text, req.CustomProviders...)
	case "csv":
		res, err = importer.ParseCSV(req.Text, req.CustomProviders...)
	default:
		writeErr(w, http.StatusBadRequest, "format must be txt or csv")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	sess, err := h.Sessions.Create(req.Format, res.Records, res.Unmatched)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	validated, ok := validate(h, w, res.Records)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":    sess.ID,
		"format":        sess.Format,
		"rows":          rowsJSON(validated),
		"unmatched":     unmatchedJSON(res.Unmatched),
		"new_providers": newProvidersJSON(res.NewProviders),
	})
}

// Validate handles POST /api/import/validate. It applies full-replacement
// edits (if any) and returns the masked, validated rows.
func (h *ImportHandler) Validate(w http.ResponseWriter, r *http.Request) {
	var req editRequest
	if err := parseBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	sess := h.Sessions.Get(strings.TrimSpace(req.SessionID))
	if sess == nil {
		writeErr(w, http.StatusNotFound, "import session not found or expired")
		return
	}
	records := sess.Records
	if len(req.Records) > 0 {
		var err error
		records, err = applyEdits(sess.Records, req.Records)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if !h.Sessions.UpdateRecords(sess.ID, records) {
			writeErr(w, http.StatusNotFound, "import session not found or expired")
			return
		}
	}
	validated, ok := validate(h, w, records)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": sess.ID,
		"rows":       rowsJSON(validated),
		"unmatched":  unmatchedJSON(sess.Unmatched),
	})
}

// Commit handles POST /api/import/commit. Duplicate modes:
//   - skip:   valid duplicates are not imported; counted in skipped
//   - import: valid duplicates are imported
//   - review: valid duplicates are not imported; returned in duplicates_review
//
// Invalid rows are never imported and are counted in attention.
func (h *ImportHandler) Commit(w http.ResponseWriter, r *http.Request) {
	sk := h.Auth.Subkeys()
	if sk == nil {
		writeErr(w, http.StatusLocked, "locked")
		return
	}
	var req commitRequest
	if err := parseBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	mode := strings.ToLower(strings.TrimSpace(req.DuplicateMode))
	if mode != "skip" && mode != "import" && mode != "review" {
		writeErr(w, http.StatusBadRequest, "duplicate_mode must be skip, import or review")
		return
	}
	sess := h.Sessions.Get(strings.TrimSpace(req.SessionID))
	if sess == nil {
		writeErr(w, http.StatusNotFound, "import session not found or expired")
		return
	}
	records := sess.Records
	if len(req.Records) > 0 {
		var err error
		records, err = applyEdits(sess.Records, req.Records)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	validated, ok := validate(h, w, records)
	if !ok {
		return
	}

	tx, err := h.DB.Begin()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback()

	providerID := map[string]int64{}
	lookupProvider := func(name string) (int64, bool, error) {
		key := strings.ToLower(name)
		if id, ok := providerID[key]; ok {
			return id, false, nil
		}
		var id int64
		err := tx.QueryRow("SELECT id FROM providers WHERE name = ? COLLATE NOCASE", name).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return 0, true, nil
		}
		if err != nil {
			return 0, false, err
		}
		providerID[key] = id
		return id, false, nil
	}

	imported, skipped, duplicates, attention, providersCreated := 0, 0, 0, 0, 0
	var review []importRowJSON

	for i, vr := range validated {
		if !vr.Valid {
			attention++
			continue
		}
		if vr.Duplicate {
			duplicates++
			switch mode {
			case "skip":
				skipped++
				continue
			case "review":
				row := rowsJSON(validated[i : i+1])[0]
				review = append(review, row)
				continue
			}
			// "import": fall through and insert
		}
		name := strings.TrimSpace(vr.Provider)
		id, create, err := lookupProvider(name)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		if create {
			res, err := tx.Exec("INSERT INTO providers (name) VALUES (?)", name)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, "internal error")
				return
			}
			id, _ = res.LastInsertId()
			providerID[strings.ToLower(name)] = id
			providersCreated++
		}
		ct, nonce, err := encryption.Seal(sk.Enc, []byte(vr.Key))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		fp := importer.Fingerprint(sk.HMAC, []byte(vr.Key))
		if _, err := tx.Exec(
			"INSERT INTO api_keys (email, provider_id, label, encrypted_key, nonce, fingerprint) VALUES (?, ?, ?, ?, ?, ?)",
			strings.TrimSpace(vr.Email), id, "", ct, nonce, fp); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		imported++
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.Sessions.Delete(sess.ID)
	resp := map[string]any{
		"format":            sess.Format,
		"imported":          imported,
		"skipped":           skipped,
		"duplicates":        duplicates,
		"attention":         attention,
		"providers_created": providersCreated,
		"unmatched":         len(sess.Unmatched),
	}
	if mode == "review" && len(review) > 0 {
		resp["duplicates_review"] = review
	}
	writeJSON(w, http.StatusOK, resp)
}
