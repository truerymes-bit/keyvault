// Package handlers contains the HTTP API handlers.
package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"keyvault/internal/security"
)

type AuthHandler struct {
	Auth *security.Auth
}

type statusResponse struct {
	Setup    bool `json:"setup"`
	Unlocked bool `json:"unlocked"`
}

type passwordRequest struct {
	Password string `json:"password"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodePassword(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req passwordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return "", false
	}
	if req.Password == "" {
		writeErr(w, http.StatusBadRequest, "password must not be empty")
		return "", false
	}
	return req.Password, true
}

// Status handles GET /api/auth/status.
func (h *AuthHandler) Status(w http.ResponseWriter, r *http.Request) {
	setup, err := h.Auth.IsSetup()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{Setup: setup, Unlocked: h.Auth.Unlocked()})
}

// Setup handles POST /api/auth/setup.
func (h *AuthHandler) Setup(w http.ResponseWriter, r *http.Request) {
	pw, ok := decodePassword(w, r)
	if !ok {
		return
	}
	if err := h.Auth.Setup(pw); err != nil {
		switch {
		case errors.Is(err, security.ErrAlreadySetup):
			writeErr(w, http.StatusConflict, "master password already set up")
		default:
			writeErr(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{Setup: true, Unlocked: true})
}

// Unlock handles POST /api/auth/unlock.
func (h *AuthHandler) Unlock(w http.ResponseWriter, r *http.Request) {
	pw, ok := decodePassword(w, r)
	if !ok {
		return
	}
	if err := h.Auth.Unlock(pw); err != nil {
		switch {
		case errors.Is(err, security.ErrNotSetup):
			writeErr(w, http.StatusConflict, "master password not set up")
		case errors.Is(err, security.ErrWrongPassword):
			writeErr(w, http.StatusUnauthorized, "wrong master password")
		default:
			writeErr(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{Setup: true, Unlocked: true})
}

// Lock handles POST /api/auth/lock.
func (h *AuthHandler) Lock(w http.ResponseWriter, r *http.Request) {
	h.Auth.Lock()
	setup, err := h.Auth.IsSetup()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, statusResponse{Setup: setup, Unlocked: false})
}
