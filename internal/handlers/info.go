package handlers

import (
	"net/http"
	"os"
	"path/filepath"

	"database/sql"
)

type infoResponse struct {
	DBFile      string  `json:"db_file"`
	DBSizeBytes int64   `json:"db_size_bytes"`
	LastBackup  *string `json:"last_backup"`
	Version     string  `json:"version"`
	Encryption  string  `json:"encryption"`
}

// Info handles GET /api/info.
func (h *InfoHandler) Info(w http.ResponseWriter, r *http.Request) {
	dbPath := h.DBPath
	fi, err := os.Stat(dbPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "stat db: "+err.Error())
		return
	}

	dbFile := filepath.Base(dbPath)
	dbSizeBytes := fi.Size()

	var lastBackup *string
	v, err := getSetting(h.DB, "last_backup")
	if err == nil && v != "" {
		lastBackup = &v
	}

	resp := infoResponse{
		DBFile:      dbFile,
		DBSizeBytes: dbSizeBytes,
		LastBackup:  lastBackup,
		Version:     "1.0.0",
		Encryption:  "AES-256-GCM",
	}

	writeJSON(w, http.StatusOK, resp)
}

// InfoHandler handles /api/info endpoints.
type InfoHandler struct {
	DB     *sql.DB
	DBPath string
}
