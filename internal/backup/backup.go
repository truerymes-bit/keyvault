// Package backup implements an encrypted, self-contained backup envelope for
// a KeyVault SQLite database. The envelope is created with VACUUM INTO (a
// consistent snapshot) and encrypted with AES-256-GCM under the backup
// subkey. The envelope is self-describing: it carries the Argon2id salt and
// parameters needed to derive the master key on a fresh machine using only
// the master password.
//
// Format (little-endian):
//
//	[magic:8] [version:u32] [salt:16] [t:u32] [m:u32] [p:u8] [dkLen:u32]
//	[nonce:12] [header:AAD] [ciphertext]
package backup

import (
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"

	"keyvault/internal/database"
	"keyvault/internal/encryption"
)

const (
	magic     = "KeyVault" // 8 bytes
	version   = 1
	saltLen   = 16
	nonceLen  = 12
	headerLen = 1024
)

// envelope is the self-contained backup container. It is not exported in the
// public API (the encode/decode functions are package-private) but is defined
// here so tests can inspect the produced bytes.
type envelope struct {
	Magic      [8]byte
	Version    uint32
	Salt       []byte
	TN         uint32
	TM         uint32
	TP         uint8
	TDkLen     uint32
	Nonce      []byte
	Header     []byte
	Ciphertext []byte
}

// Encode builds an encrypted backup envelope from the SQLite database at
// dbPath. The argon2id parameters (salt, time, memory, threads) and the
// backup subkey are supplied by the caller; a backup created on one machine
// is portable to another given only the master password.
func Encode(dbPath string, backupKey, salt []byte, t, m uint32, p uint8, dkLen uint32) ([]byte, error) {
	// Open the database to get a single-writer connection.
	db, err := database.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	// VACUUM INTO to a temp file creates a consistent snapshot.
	tmp, err := os.CreateTemp("", "keyvault-backup-*.db")
	if err != nil {
		return nil, fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpName)

	// VACUUM INTO must run on the single shared connection (MaxOpenConns=1).
	if _, err := db.Exec("VACUUM INTO '" + tmpName + "'"); err != nil {
		return nil, fmt.Errorf("vacuum into: %w", err)
	}

	// Read the snapshot bytes.
	data, err := os.ReadFile(tmpName)
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	if err := os.Remove(tmpName); err != nil {
		// Best effort; snapshot bytes are already in memory.
	}

	header := data[:min(headerLen, len(data))]
	body := data[headerLen:]

	// Generate a fresh nonce for AES-GCM.
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	gcm, err := encryption.NewGCM(backupKey)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, body, header)

	// Build and return the envelope.
	return encodeEnvelope(salt, t, m, p, dkLen, nonce, header, ciphertext), nil
}

// Decode reads and decrypts a backup envelope, returning the plaintext SQL.
func Decode(b []byte, key []byte) ([]byte, error) {
	if len(b) < 8+4+16+4+4+1+4+12 {
		return nil, errors.New("backup file too short")
	}
	if string(b[0:8]) != magic {
		return nil, fmt.Errorf("invalid magic: %x", b[0:8])
	}
	if binary.LittleEndian.Uint32(b[8:12]) != version {
		return nil, fmt.Errorf("unsupported version %d", binary.LittleEndian.Uint32(b[8:12]))
	}
	// Skip metadata (salt, t, m, p, dkLen) we don't need for decryption.
	if len(b) < 53+1024 {
		return nil, errors.New("backup file too short")
	}
	nonce := b[41 : 41+12]
	headerStart := 53
	header := b[headerStart : headerStart+1024]
	if len(b) < headerStart+1024 {
		return nil, errors.New("backup file too short for header")
	}
	ciphertext := b[headerStart+1024:]

	gcm, err := encryption.NewGCM(key)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

func encodeEnvelope(salt []byte, t, m uint32, p uint8, dkLen uint32, nonce, header, ciphertext []byte) []byte {
	var buf []byte
	buf = append(buf, magic...)
	buf = append(buf, byte(version), byte(0), byte(0), byte(0))
	buf = append(buf, salt...)
	buf = append(buf, byte(t), byte(t>>8), byte(t>>16), byte(t>>24))
	buf = append(buf, byte(m), byte(m>>8), byte(m>>16), byte(m>>24))
	buf = append(buf, p)
	buf = append(buf, byte(dkLen), byte(dkLen>>8), byte(dkLen>>16), byte(dkLen>>24))
	buf = append(buf, nonce...)
	buf = append(buf, header...)
	buf = append(buf, ciphertext...)
	return buf
}

// DeriveMasterKeyFromBackup derives the master key from the stored argon2id
// parameters. The salt and parameters are read from the envelope, so a backup
// is portable across machines using only the master password.
func DeriveMasterKeyFromBackup(password string, salt []byte, t, m uint32, p uint8, dkLen uint32) []byte {
	return argon2.IDKey([]byte(password), salt, t, m, p, dkLen)
}

// getSetting reads a settings row by key.
func getSetting(db *sql.DB, key string) (string, error) {
	var v string
	if err := db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&v); err != nil {
		return "", err
	}
	return v, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
