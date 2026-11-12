package security

import (
	"errors"
	"path/filepath"
	"testing"

	"keyvault/internal/database"
)

func openTemp(t *testing.T) *Auth {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewAuth(db)
}

func TestFirstTimeSetup(t *testing.T) {
	a := openTemp(t)
	setup, err := a.IsSetup()
	if err != nil || setup {
		t.Fatalf("IsSetup = %v, %v; want false, nil", setup, err)
	}
	if err := a.Setup("hunter2"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if !a.Unlocked() {
		t.Fatal("expected unlocked after setup")
	}
	setup, _ = a.IsSetup()
	if !setup {
		t.Fatal("expected IsSetup true after setup")
	}
	if err := a.Setup("again"); !errors.Is(err, ErrAlreadySetup) {
		t.Fatalf("second Setup err = %v, want ErrAlreadySetup", err)
	}
}

func TestWrongPasswordRejected(t *testing.T) {
	a := openTemp(t)
	if err := a.Setup("hunter2"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	a.Lock()
	if err := a.Unlock("wrong"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("Unlock err = %v, want ErrWrongPassword", err)
	}
	if a.Unlocked() {
		t.Fatal("must remain locked after wrong password")
	}
}

func TestCorrectPasswordUnlocks(t *testing.T) {
	a := openTemp(t)
	if err := a.Setup("hunter2"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	a.Lock()
	if a.Unlocked() {
		t.Fatal("expected locked after Lock")
	}
	if err := a.Unlock("hunter2"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if !a.Unlocked() {
		t.Fatal("expected unlocked after correct password")
	}
}

func TestLockClearsKey(t *testing.T) {
	a := openTemp(t)
	if err := a.Setup("hunter2"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	sub := a.Subkeys()
	if sub == nil {
		t.Fatal("expected subkeys while unlocked")
	}
	a.Lock()
	if a.Subkeys() != nil {
		t.Fatal("expected nil subkeys after Lock")
	}
	for i, b := range sub.Enc {
		if b != 0 {
			t.Fatalf("enc subkey byte %d not zeroed", i)
		}
	}
}

func TestUnlockBeforeSetup(t *testing.T) {
	a := openTemp(t)
	if err := a.Unlock("hunter2"); !errors.Is(err, ErrNotSetup) {
		t.Fatalf("Unlock err = %v, want ErrNotSetup", err)
	}
}

func TestUnlockPersistsAcrossInstances(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	a1 := NewAuth(db)
	if err := a1.Setup("hunter2"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	db.Close()

	db2, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	a2 := NewAuth(db2)
	if err := a2.Unlock("hunter2"); err != nil {
		t.Fatalf("Unlock after reopen: %v", err)
	}
}
