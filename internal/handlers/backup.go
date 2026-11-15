package handlers

import (
	"database/sql"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"keyvault/internal/backup"
	"keyvault/internal/security"
)

// BackupHandler handles encrypted local backup and restore operations.
type BackupHandler struct {
	DB     *sql.DB
	DBPath string
	Auth   *security.Auth
}

// writeDownload writes a file download response.
func writeDownload(w http.ResponseWriter, filename string, data []byte) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// Backup handles POST /api/backup: downloads an encrypted backup file.
func (h *BackupHandler) Backup(w http.ResponseWriter, r *http.Request) {
	if h.Auth == nil || !h.Auth.Unlocked() {
		writeErr(w, http.StatusUnauthorized, "vault is locked")
		return
	}
	sub := h.Auth.Subkeys()
	if sub == nil || sub.Backup == nil {
		writeErr(w, http.StatusInternalServerError, "backup subkey not ready")
		return
	}

	saltB64, err := getSetting(h.DB, "argon_salt")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "read argon_salt: "+err.Error())
		return
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "decode salt: "+err.Error())
		return
	}
	t, m, p := readArgonParams(h.DB)

	enc, err := backup.Encode(h.DBPath, sub.Backup, salt, t, m, p, 32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create backup: "+err.Error())
		return
	}

	fn := "keyvault-backup-" + time.Now().UTC().Format("20060102-150405") + ".kbk"
	writeDownload(w, fn, enc)
}

// Restore handles POST /api/restore: uploads an encrypted backup file and
// replaces the current database after creating a rollback copy and verifying
// the envelope.
func (h *BackupHandler) Restore(w http.ResponseWriter, r *http.Request) {
	if h.Auth == nil || !h.Auth.Unlocked() {
		writeErr(w, http.StatusUnauthorized, "vault is locked")
		return
	}
	sub := h.Auth.Subkeys()
	if sub == nil || sub.Backup == nil {
		writeErr(w, http.StatusInternalServerError, "backup subkey not ready")
		return
	}

	if err := r.ParseMultipartForm(1 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid multipart: "+err.Error())
		return
	}
	file, _, err := r.FormFile("backup")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "missing backup file: "+err.Error())
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "read backup file: "+err.Error())
		return
	}

	if len(data) < 8+4+16+4+4+1+4+12 {
		writeErr(w, http.StatusBadRequest, "backup file too short")
		return
	}
	if string(data[0:8]) != backupMagic {
		writeErr(w, http.StatusBadRequest, "invalid backup magic")
		return
	}
	ver := binaryReadU32(data[8:12])
	if ver != 1 {
		writeErr(w, http.StatusBadRequest, "unsupported backup version")
		return
	}

	plaintext, err := backup.Decode(data, sub.Backup)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "backup decryption failed: "+err.Error())
		return
	}

	if len(plaintext) < 1024 {
		writeErr(w, http.StatusBadRequest, "backup does not contain a valid database")
		return
	}

	// Write the decrypted snapshot to a temp file so SQLite can ATTACH it.
	tmp, err := os.CreateTemp("", "keyvault-restore-*.db")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create restore tmp: "+err.Error())
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(plaintext); err != nil {
		tmp.Close()
		writeErr(w, http.StatusInternalServerError, "write restore tmp: "+err.Error())
		return
	}
	if err := tmp.Close(); err != nil {
		writeErr(w, http.StatusInternalServerError, "close restore tmp: "+err.Error())
		return
	}

	dir := filepath.Dir(h.DBPath)
	rollbackPath := dir + "/keyvault.db.rollback." + time.Now().UTC().Format("20060102-150405")
	// Snapshot the current DB using VACUUM INTO for consistency.
	if _, err := h.DB.Exec("VACUUM INTO '" + rollbackPath + "'"); err != nil {
		writeErr(w, http.StatusInternalServerError, "create rollback snapshot: "+err.Error())
		return
	}

	if err := restoreLive(h.DB, tmpName); err != nil {
		writeErr(w, http.StatusInternalServerError, "apply restore: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":      "restored",
		"backup_date": time.Now().UTC().Format(time.RFC3339),
		"rollback":    rollbackPath,
	})
}

// restoreLive copies every row from the snapshot database into the live one.
// ATTACH-based restore keeps the running server consistent: replacing the
// file on disk would leave the open connection reading stale pages.
func restoreLive(db *sql.DB, snapshotPath string) error {
	if _, err := db.Exec("ATTACH ? AS restore_src", snapshotPath); err != nil {
		return err
	}
	defer db.Exec("DETACH restore_src")

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// api_keys first: providers is RESTRICTed by the foreign key.
	for _, q := range []string{
		"DELETE FROM api_keys",
		"DELETE FROM providers",
		"DELETE FROM settings",
		"INSERT INTO settings (key, value) SELECT key, value FROM restore_src.settings",
		"INSERT INTO providers (id, name, notes, created_at, updated_at) SELECT id, name, notes, created_at, updated_at FROM restore_src.providers",
		"INSERT INTO api_keys (id, email, provider_id, label, encrypted_key, nonce, fingerprint, created_at, updated_at) SELECT id, email, provider_id, label, encrypted_key, nonce, fingerprint, created_at, updated_at FROM restore_src.api_keys",
	} {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// readArgonParams reads the argon2id parameters from settings.
func readArgonParams(db *sql.DB) (uint32, uint32, uint8) {
	t := uint32(3)
	m := uint32(65536)
	p := uint8(2)
	if v, err := getSetting(db, "argon_time"); err == nil {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			t = uint32(n)
		}
	}
	if v, err := getSetting(db, "argon_memory"); err == nil {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			m = uint32(n)
		}
	}
	if v, err := getSetting(db, "argon_threads"); err == nil {
		if n, err := strconv.ParseUint(v, 10, 8); err == nil {
			p = uint8(n)
		}
	}
	return t, m, p
}

// getSetting reads a settings row by key.
func getSetting(db *sql.DB, key string) (string, error) {
	var v string
	if err := db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&v); err != nil {
		return "", err
	}
	return v, nil
}

// backupMagic is the envelope magic bytes.
const backupMagic = "KeyVault"

// binaryReadU32 reads a little-endian uint32.
func binaryReadU32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
