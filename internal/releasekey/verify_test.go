package releasekey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sign(priv ed25519.PrivateKey, tag, platform, sum string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, Message(tag, platform, sum)))
}

const sum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

// The message is the one agreed with bld's signing side, byte for byte.
func TestMessageIsTheAgreedFormat(t *testing.T) {
	got := string(Message("v2026.10.27", "windows-amd64", sum))
	want := "MyGHAgent client release\nv2026.10.27\nwindows-amd64\n" + sum + "\n"
	if got != want {
		t.Errorf("Message = %q, want %q", got, want)
	}
	if Message("v1\nwindows-amd64", "x", sum) != nil {
		t.Error("a field with a newline must be refused")
	}
}

func TestVerify(t *testing.T) {
	pub, priv := newKey(t)
	other, _ := newKey(t)
	sig := sign(priv, "v2026.10.27", "linux-amd64", sum)
	keys := []ed25519.PublicKey{other, pub}

	if !Verify(keys, "v2026.10.27", "linux-amd64", sum, sig) {
		t.Fatal("a good signature did not verify")
	}
	for name, ok := range map[string]bool{
		"other tag":      Verify(keys, "v2026.10.28", "linux-amd64", sum, sig),
		"other platform": Verify(keys, "v2026.10.27", "darwin-arm64", sum, sig),
		"other sha":      Verify(keys, "v2026.10.27", "linux-amd64", sum[:63]+"9", sig),
		"foreign key":    Verify([]ed25519.PublicKey{other}, "v2026.10.27", "linux-amd64", sum, sig),
		"no keys":        Verify(nil, "v2026.10.27", "linux-amd64", sum, sig),
		"not base64":     Verify(keys, "v2026.10.27", "linux-amd64", sum, "!!!"),
		"short":          Verify(keys, "v2026.10.27", "linux-amd64", sum, base64.StdEncoding.EncodeToString([]byte("x"))),
	} {
		if ok {
			t.Errorf("%s: verified", name)
		}
	}
}

func TestKeys(t *testing.T) {
	pub, _ := newKey(t)
	old := ExtraKeyHex
	t.Cleanup(func() { ExtraKeyHex = old })

	ExtraKeyHex = PublicHex(pub)
	keys, err := Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 || !keys[len(keys)-1].Equal(pub) {
		t.Errorf("keys = %v, want the extra key last", keys)
	}

	ExtraKeyHex = "not-hex"
	if _, err := Keys(); err == nil {
		t.Error("a malformed compiled-in key must be an error")
	}
	ExtraKeyHex = "abcd"
	if _, err := Keys(); err == nil {
		t.Error("a short compiled-in key must be an error")
	}
}

func TestFingerprintIsShortAndStable(t *testing.T) {
	pub, _ := newKey(t)
	if fp := Fingerprint(pub); len(fp) != 16 || fp != Fingerprint(pub) {
		t.Errorf("fingerprint = %q", fp)
	}
}
