package encryption

import (
	"bytes"
	"testing"
)

func testKeys(t *testing.T) (Subkeys, []byte) {
	t.Helper()
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	master := DeriveMasterKey("correct horse battery staple", salt)
	sk, err := DeriveSubkeys(master)
	if err != nil {
		t.Fatalf("DeriveSubkeys: %v", err)
	}
	return sk, master
}

func TestRoundTrip(t *testing.T) {
	sk, _ := testKeys(t)
	plaintext := []byte("sk-test-1234567890abcdef")
	ct, nonce, err := Seal(sk.Enc, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := Open(sk.Enc, ct, nonce)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	sk, _ := testKeys(t)
	ct, nonce, err := Seal(sk.Enc, []byte("secret"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	ct[0] ^= 0xff
	if _, err := Open(sk.Enc, ct, nonce); err == nil {
		t.Fatal("expected tampered ciphertext to fail")
	}
}

func TestWrongKeyFails(t *testing.T) {
	sk, _ := testKeys(t)
	other, _ := testKeys(t)
	ct, nonce, err := Seal(sk.Enc, []byte("secret"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := Open(other.Enc, ct, nonce); err == nil {
		t.Fatal("expected wrong key to fail")
	}
}

func TestNonceUniqueness(t *testing.T) {
	sk, _ := testKeys(t)
	seen := make(map[string]struct{})
	for i := 0; i < 1000; i++ {
		_, nonce, err := Seal(sk.Enc, []byte("same plaintext"))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		key := string(nonce)
		if _, dup := seen[key]; dup {
			t.Fatal("nonce reused")
		}
		seen[key] = struct{}{}
	}
}

func TestSubkeysDistinct(t *testing.T) {
	sk, _ := testKeys(t)
	if bytes.Equal(sk.Enc, sk.HMAC) || bytes.Equal(sk.Enc, sk.Backup) || bytes.Equal(sk.HMAC, sk.Backup) {
		t.Fatal("subkeys must be distinct")
	}
	for name, k := range map[string][]byte{"enc": sk.Enc, "hmac": sk.HMAC, "backup": sk.Backup} {
		if len(k) != KeyLen {
			t.Fatalf("%s subkey len = %d, want %d", name, len(k), KeyLen)
		}
	}
}

func TestDeterministicDerivation(t *testing.T) {
	salt := make([]byte, SaltLen)
	for i := range salt {
		salt[i] = byte(i)
	}
	m1 := DeriveMasterKey("pw", salt)
	m2 := DeriveMasterKey("pw", salt)
	if !bytes.Equal(m1, m2) {
		t.Fatal("same password and salt must derive the same master key")
	}
}
