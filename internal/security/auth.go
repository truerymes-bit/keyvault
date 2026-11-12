// Package security holds the in-memory authentication state: master-key
// subkeys derived from the master password, setup verifier handling, and
// lock/unlock. Keys exist only in memory while unlocked.
package security

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"

	"keyvault/internal/encryption"
)

const (
	settingSalt     = "argon_salt"
	settingTime     = "argon_time"
	settingMemory   = "argon_memory"
	settingThreads  = "argon_threads"
	settingVerifier = "verifier"

	verifierPlaintext = "keyvault-verifier-v1"
)

var (
	ErrAlreadySetup  = errors.New("master password already set up")
	ErrNotSetup      = errors.New("master password not set up")
	ErrWrongPassword = errors.New("wrong master password")
)

// Auth manages the unlocked state. The zero value is ready to use but locked.
type Auth struct {
	db      *sql.DB
	subkeys *encryption.Subkeys
}

func NewAuth(db *sql.DB) *Auth {
	return &Auth{db: db}
}

// IsSetup reports whether a master password has been configured.
func (a *Auth) IsSetup() (bool, error) {
	var v string
	err := a.db.QueryRow("SELECT value FROM settings WHERE key = ?", settingVerifier).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check setup: %w", err)
	}
	return true, nil
}

// Unlocked reports whether the master key is currently held in memory.
func (a *Auth) Unlocked() bool {
	return a.subkeys != nil
}

// Subkeys returns the in-memory subkeys, or nil while locked.
func (a *Auth) Subkeys() *encryption.Subkeys {
	return a.subkeys
}

// Setup configures the master password for the first time and unlocks.
func (a *Auth) Setup(password string) error {
	if password == "" {
		return errors.New("password must not be empty")
	}
	setup, err := a.IsSetup()
	if err != nil {
		return err
	}
	if setup {
		return ErrAlreadySetup
	}
	salt, err := encryption.GenerateSalt()
	if err != nil {
		return err
	}
	master := encryption.DeriveMasterKey(password, salt)
	sk, err := encryption.DeriveSubkeys(master)
	if err != nil {
		return err
	}
	ct, nonce, err := encryption.Seal(sk.Enc, []byte(verifierPlaintext))
	if err != nil {
		return err
	}
	verifier := append(nonce, ct...)

	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	stmts := []struct{ k, v string }{
		{settingSalt, base64.StdEncoding.EncodeToString(salt)},
		{settingTime, fmt.Sprintf("%d", encryption.ArgonTime)},
		{settingMemory, fmt.Sprintf("%d", encryption.ArgonMemory)},
		{settingThreads, fmt.Sprintf("%d", encryption.ArgonThreads)},
		{settingVerifier, base64.StdEncoding.EncodeToString(verifier)},
	}
	for _, s := range stmts {
		if _, err := tx.Exec("INSERT INTO settings (key, value) VALUES (?, ?)", s.k, s.v); err != nil {
			tx.Rollback()
			return fmt.Errorf("store %s: %w", s.k, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	a.subkeys = &sk
	return nil
}

// Unlock verifies the password against the stored verifier and holds the
// derived subkeys in memory on success.
func (a *Auth) Unlock(password string) error {
	setup, err := a.IsSetup()
	if err != nil {
		return err
	}
	if !setup {
		return ErrNotSetup
	}
	saltB64, err := getSetting(a.db, settingSalt)
	if err != nil {
		return err
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return fmt.Errorf("decode salt: %w", err)
	}
	verifierB64, err := getSetting(a.db, settingVerifier)
	if err != nil {
		return err
	}
	verifier, err := base64.StdEncoding.DecodeString(verifierB64)
	if err != nil {
		return fmt.Errorf("decode verifier: %w", err)
	}
	if len(verifier) <= encryption.NonceLen {
		return errors.New("stored verifier is malformed")
	}
	master := encryption.DeriveMasterKey(password, salt)
	sk, err := encryption.DeriveSubkeys(master)
	if err != nil {
		return err
	}
	nonce, ct := verifier[:encryption.NonceLen], verifier[encryption.NonceLen:]
	plaintext, err := encryption.Open(sk.Enc, ct, nonce)
	if err != nil || string(plaintext) != verifierPlaintext {
		return ErrWrongPassword
	}
	a.subkeys = &sk
	return nil
}

// Lock clears the in-memory subkeys.
func (a *Auth) Lock() {
	if a.subkeys != nil {
		for _, k := range [][]byte{a.subkeys.Enc, a.subkeys.HMAC, a.subkeys.Backup} {
			for i := range k {
				k[i] = 0
			}
		}
		a.subkeys = nil
	}
}

func getSetting(db *sql.DB, key string) (string, error) {
	var v string
	if err := db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&v); err != nil {
		return "", fmt.Errorf("read setting %s: %w", key, err)
	}
	return v, nil
}
