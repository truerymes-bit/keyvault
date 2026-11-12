// Package encryption implements the KeyVault key hierarchy:
// Argon2id(master password, salt) -> master key -> HKDF-SHA256 subkeys
// (keyvault/enc, keyvault/hmac, keyvault/backup). Plaintext keys are sealed
// with AES-256-GCM under a fresh random nonce.
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	// Argon2id parameters. Memory is in KiB.
	ArgonTime    uint32 = 3
	ArgonMemory  uint32 = 64 * 1024
	ArgonThreads uint8  = 2
	KeyLen              = 32
	SaltLen             = 16
	NonceLen            = 12

	InfoEnc    = "keyvault/enc"
	InfoHMAC   = "keyvault/hmac"
	InfoBackup = "keyvault/backup"
)

// Subkeys derived from the master key.
type Subkeys struct {
	Enc    []byte
	HMAC   []byte
	Backup []byte
}

// GenerateSalt returns a random Argon2id salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

// DeriveMasterKey derives the master key from a password and salt using Argon2id.
func DeriveMasterKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, ArgonTime, ArgonMemory, ArgonThreads, KeyLen)
}

// DeriveSubkeys expands the master key into the enc, hmac and backup subkeys.
func DeriveSubkeys(master []byte) (Subkeys, error) {
	var sk Subkeys
	for _, d := range []struct {
		dest *[]byte
		info string
	}{{&sk.Enc, InfoEnc}, {&sk.HMAC, InfoHMAC}, {&sk.Backup, InfoBackup}} {
		r := hkdf.New(sha256.New, master, nil, []byte(d.info))
		buf := make([]byte, KeyLen)
		if _, err := io.ReadFull(r, buf); err != nil {
			return Subkeys{}, fmt.Errorf("derive subkey %q: %w", d.info, err)
		}
		*d.dest = buf
	}
	return sk, nil
}

// Seal encrypts plaintext with AES-256-GCM under key, returning ciphertext
// and the fresh random nonce used.
func Seal(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	gcm, err := gcmFor(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, NonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nonce, nil
}

// Open decrypts ciphertext with AES-256-GCM under key and nonce.
func Open(key, ciphertext, nonce []byte) ([]byte, error) {
	gcm, err := gcmFor(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed")
	}
	return plaintext, nil
}

func gcmFor(key []byte) (cipher.AEAD, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("key must be %d bytes, got %d", KeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	return cipher.NewGCM(block)
}
