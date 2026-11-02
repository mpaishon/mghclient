package releasekey

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func TestMessageIsTheFixedContract(t *testing.T) {
	got := string(Message("v2026.10.27", "windows-amd64", "ABCDEF"))
	want := "MyGHAgent client release\nv2026.10.27\nwindows-amd64\nabcdef\n"
	if got != want {
		t.Fatalf("Message = %q, want %q", got, want)
	}
	for _, bad := range [][3]string{{"", "p", "s"}, {"v1\nx", "p", "s"}, {"v1", "p\r", "s"}} {
		if Message(bad[0], bad[1], bad[2]) != nil {
			t.Errorf("Message%q accepted", bad)
		}
	}
}

func TestSignRoundTripsThroughTheKeyFile(t *testing.T) {
	priv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := MarshalPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParsePrivateKey(pemBytes)
	if err != nil || !back.Equal(priv) {
		t.Fatalf("key file round trip: %v", err)
	}
	sig, err := Sign(back, "v1", "linux-amd64", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(sig, "\r\n ") {
		t.Errorf("signature %q is not one bare line", sig)
	}
	raw, _ := base64.StdEncoding.DecodeString(sig)
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), Message("v1", "linux-amd64", strings.Repeat("a", 64)), raw) {
		t.Error("the signature does not verify over Message")
	}
	if _, err := ParsePrivateKey([]byte("not pem")); err == nil {
		t.Error("garbage parsed as a key")
	}
	if len(Fingerprint(priv.Public().(ed25519.PublicKey))) != 16 || len(PublicHex(priv.Public().(ed25519.PublicKey))) != 64 {
		t.Error("fingerprint or hex length")
	}
}
