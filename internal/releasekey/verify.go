package releasekey

// The verify side. The public
// half of the release key is compiled into mghagent, so a client can tell a
// build this household released from anything else, whatever relay handed
// it over: a compromised relay can at most offer an older genuine release.
//
// The signature covers Message(tag, platform, sha256): the release tag, the
// goos-arch the zip is for, and the SHA-256 of the zip itself. bld release
// signs exactly this message with the private half, which
// lives outside the repository.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// PrimaryHex is the public half of the household's mghagent release key,
// hex, as `go run ./bld keygen` prints it. Empty means no key is compiled in:
// the client then accepts no update at all (clientupdate.ErrNoKey) rather
// than trusting whatever the relay offers. The key is generated outside the
// repository by the owner; pasting its public half here is a release step.
const PrimaryHex = "20aa0ae206ff9e784f1e3c7c27f847a60d3482ea0921901cfeae2c1659d7548a"

// ExtraKeyHex is a second public key, set by the linker only (-X
// github.com/mpaishon/MyGHAgent/internal/releasekey.ExtraKeyHex=<hex>): a key
// being rotated in. Tests set it directly.
var ExtraKeyHex string

// MessageHeader is the first line of every signed release message, so a
// signature made for a client release can never pass as one for anything
// else (other products use their own header).
const MessageHeader = "MyGHAgent client release\n"

// Keys are the public keys compiled in, PrimaryHex first. A value that is not
// a key is an error, never silently no key.
func Keys() ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for _, h := range []struct{ name, hex string }{{"PrimaryHex", PrimaryHex}, {"ExtraKeyHex", ExtraKeyHex}} {
		if h.hex == "" {
			continue
		}
		key, err := ParsePublicHex(h.hex)
		if err != nil {
			return nil, fmt.Errorf("releasekey.%s: %w", h.name, err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// ParsePublicHex reads a public key as keygen prints it.
func ParsePublicHex(h string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil {
		return nil, fmt.Errorf("not hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%d bytes, want an Ed25519 public key of %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// PublicHex is a public key as PrimaryHex holds it.
func PublicHex(pub ed25519.PublicKey) string { return hex.EncodeToString(pub) }

// Fingerprint names a key in logs and build output: the first 16 hex digits
// of the SHA-256 of the public key.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// Message is what a release signature covers:
// "MyGHAgent client release\n<tag>\n<goos-arch>\n<sha256>\n". An empty field,
// or one holding a line break, is refused (nil), so fields cannot be shifted
// into one another. Sign and Verify both build their bytes here.
func Message(tag, platform, sha256hex string) []byte {
	for _, f := range []string{tag, platform, sha256hex} {
		if f == "" || strings.ContainsAny(f, "\r\n") {
			return nil
		}
	}
	return []byte(MessageHeader + tag + "\n" + platform + "\n" + strings.ToLower(sha256hex) + "\n")
}

// Verify reports whether signature (base64, as the .sig asset and the update
// offer carry it) was made over the release message by one of keys. A
// signature that is not even base64 is false, not an error: it is just not
// a valid signature.
func Verify(keys []ed25519.PublicKey, tag, platform, sha256hex, signature string) bool {
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg := Message(tag, platform, sha256hex)
	if msg == nil {
		return false
	}
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, msg, sig) {
			return true
		}
	}
	return false
}
