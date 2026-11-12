package handlers

import (
	"database/sql"
	"net/http"
)

type DashboardHandler struct {
	DB *sql.DB
}

type dashboardResponse struct {
	TotalKeys      int       `json:"total_keys"`
	TotalProviders int       `json:"total_providers"`
	TotalEmails    int       `json:"total_emails"`
	RecentKeys     []keyJSON `json:"recent_keys"`
	RecentModified []keyJSON `json:"recent_modified"`
}

// Stats handles GET /api/dashboard. Key lists are masked.
func (h *DashboardHandler) Stats(w http.ResponseWriter, r *http.Request) {
	var resp dashboardResponse
	err := h.DB.QueryRow(`
SELECT (SELECT count(*) FROM api_keys),
       (SELECT count(*) FROM providers),
       (SELECT count(DISTINCT email) FROM api_keys)`).
		Scan(&resp.TotalKeys, &resp.TotalProviders, &resp.TotalEmails)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	var errKeys, errMod error
	resp.RecentKeys, errKeys = h.recent("k.created_at")
	resp.RecentModified, errMod = h.recent("k.updated_at")
	if errKeys != nil || errMod != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *DashboardHandler) recent(orderCol string) ([]keyJSON, error) {
	rows, err := h.DB.Query(keySelect + " ORDER BY " + orderCol + " DESC, k.id DESC LIMIT 5")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []keyJSON{}
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
