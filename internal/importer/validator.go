package importer

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
)

var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// ValidatedRecord is a parsed record after validation and duplicate
// detection. Duplicate is orthogonal to Valid: duplicates are still
// importable depending on the user's duplicate mode.
type ValidatedRecord struct {
	Record
	Fingerprint     []byte   `json:"-"`
	Valid           bool     `json:"valid"`
	Errors          []string `json:"errors,omitempty"`
	Duplicate       bool     `json:"duplicate"`
	DuplicateSource string   `json:"duplicate_source,omitempty"` // "file" or "database"
}

// Fingerprint computes the HMAC-SHA256 fingerprint of a plaintext key under
// the HMAC subkey. Exported so handlers can reuse it.
func Fingerprint(hmacSubkey, plaintext []byte) []byte {
	h := hmac.New(sha256.New, hmacSubkey)
	h.Write(plaintext)
	return h.Sum(nil)
}

// ValidateRecords validates emails and keys, assigns fingerprints, and flags
// duplicates both within the batch and against existing database records.
// Duplicate matching uses email + provider name + fingerprint (case-insensitive
// for email and provider). No plaintext hash is stored or returned.
func ValidateRecords(db *sql.DB, hmacSubkey []byte, records []Record) ([]ValidatedRecord, error) {
	out := make([]ValidatedRecord, 0, len(records))
	seen := make(map[string]int, len(records))

	for i, rec := range records {
		vr := ValidatedRecord{Record: rec, Valid: true}
		email := strings.ToLower(strings.TrimSpace(rec.Email))
		provider := strings.ToLower(strings.TrimSpace(rec.Provider))

		if !emailRe.MatchString(strings.TrimSpace(rec.Email)) {
			vr.Valid = false
			vr.Errors = append(vr.Errors, "invalid email address")
		}
		if strings.TrimSpace(rec.Key) == "" {
			vr.Valid = false
			vr.Errors = append(vr.Errors, "key must not be empty")
		}
		if rec.Status == StatusNoProvider || strings.TrimSpace(rec.Provider) == "" {
			vr.Valid = false
			vr.Errors = append(vr.Errors, "no provider assigned")
		}

		if strings.TrimSpace(rec.Key) != "" {
			vr.Fingerprint = Fingerprint(hmacSubkey, []byte(rec.Key))
			batchKey := email + "|" + provider + "|" + string(vr.Fingerprint)
			if first, dup := seen[batchKey]; dup {
				vr.Duplicate = true
				vr.DuplicateSource = "file"
				_ = first
			} else {
				seen[batchKey] = i
			}
		}
		out = append(out, vr)
	}

	// Database duplicate check. Only records with a fingerprint and a
	// provider can match.
	for i := range out {
		if out[i].Duplicate || len(out[i].Fingerprint) == 0 || strings.TrimSpace(out[i].Provider) == "" {
			continue
		}
		var id int64
		err := db.QueryRow(`
SELECT k.id FROM api_keys k
JOIN providers p ON p.id = k.provider_id
WHERE lower(k.email) = lower(?) AND lower(p.name) = lower(?) AND k.fingerprint = ?
LIMIT 1`, strings.TrimSpace(out[i].Email), strings.TrimSpace(out[i].Provider), out[i].Fingerprint).Scan(&id)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("duplicate lookup: %w", err)
		}
		out[i].Duplicate = true
		out[i].DuplicateSource = "database"
	}
	return out, nil
}
