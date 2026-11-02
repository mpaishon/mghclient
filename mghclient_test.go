package mghclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigNeedsAppAndStateDir(t *testing.T) {
	if _, err := Open(Config{App: "x"}); err == nil {
		t.Fatal("Open without a state folder was accepted")
	}
	if _, err := Open(Config{App: "x", StateDir: t.TempDir()}); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("Open of an empty folder = %v, want ErrNotEnrolled", err)
	}
	if got := StatusOf(Config{App: "x", StateDir: t.TempDir()}); got != NotEnrolled {
		t.Fatalf("status = %v", got)
	}
}

func TestStatusSeesAPendingRequest(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pending.json"), []byte(`{"app":"x","token":"t"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := StatusOf(Config{App: "x", StateDir: dir}); got != Waiting {
		t.Fatalf("status = %v, want Waiting", got)
	}
}

// TestSignatureGate: with signing keys, an offer must carry a signature
// over (version, platform, sha256) by one of them; without keys nothing is
// required.
func TestSignatureGate(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	sum := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	sig, err := SignRelease(priv, "v2026.11.01", "linux-amd64", sum)
	if err != nil {
		t.Fatal(err)
	}
	offer := &Offer{Version: "v2026.11.01", Platform: "linux-amd64", SHA256: sum, Signature: sig, AssetID: 1}

	if err := (&Instance{}).verifySignature(offer); err != nil {
		t.Fatalf("unsigned app refused an offer: %v", err)
	}
	signed := &Instance{cfg: Config{SigningKeys: []ed25519.PublicKey{other, pub}}}
	if err := signed.verifySignature(offer); err != nil {
		t.Fatalf("a good signature = %v", err)
	}
	for name, mod := range map[string]func(o *Offer){
		"no signature":     func(o *Offer) { o.Signature = "" },
		"other version":    func(o *Offer) { o.Version = "v2026.11.02" },
		"other platform":   func(o *Offer) { o.Platform = "darwin-arm64" },
		"other digest":     func(o *Offer) { o.SHA256 = "00" + sum[2:] },
		"garbage":          func(o *Offer) { o.Signature = "not base64!" },
		"no digest at all": func(o *Offer) { o.SHA256 = "" },
	} {
		o := *offer
		mod(&o)
		if err := signed.verifySignature(&o); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s = %v, want ErrBadSignature", name, err)
		}
	}
	if !VerifyRelease([]ed25519.PublicKey{pub}, "v2026.11.01", "linux-amd64", sum, sig) {
		t.Fatal("VerifyRelease refused its own signature")
	}
	k, err := ParsePublicKey(publicHex(pub))
	if err != nil || !k.Equal(pub) {
		t.Fatalf("ParsePublicKey = %v %v", k, err)
	}
}

func publicHex(p ed25519.PublicKey) string {
	const digits = "0123456789abcdef"
	b := make([]byte, 0, len(p)*2)
	for _, c := range p {
		b = append(b, digits[c>>4], digits[c&15])
	}
	return string(b)
}
