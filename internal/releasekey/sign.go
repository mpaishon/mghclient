package releasekey

// The signing side (A1, used by bld): signing the release message and the
// key file. The verifying side
// — the compiled-in public keys and Verify — is in verify.go.
//
// The contract (fixed by the lead): bld release signs each mghagent release
// zip. The signature is Ed25519 over
//
//	"MyGHAgent client release\n<tag>\n<goos-arch>\n<sha256 of the zip file, lowercase hex>\n"
//
// and is uploaded beside the zip as the asset "<zip name>.sig", holding the
// base64 signature on one line and nothing else. It covers the zip's hash,
// not the binary inside, because the relay offers and serves the zip.
//
// Message, MessageHeader, PublicHex and Fingerprint live in verify.go and are
// shared by both sides, so Sign and Verify build the very same bytes.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// SigSuffix names a zip's signature asset: <zip name> + SigSuffix.
const SigSuffix = ".sig"

// Sign signs one release zip's message; the result is base64, as the .sig
// asset holds it.
func Sign(priv ed25519.PrivateKey, tag, platform, sha256hex string) (string, error) {
	msg := Message(tag, platform, sha256hex)
	if msg == nil {
		return "", errors.New("releasekey: a release message field is empty or holds a line break")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("releasekey: not an Ed25519 private key")
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)), nil
}

// Generate makes a new release key.
func Generate() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// MarshalPrivateKey is the key as the key file holds it: PKCS#8, PEM.
func MarshalPrivateKey(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePrivateKey reads a key file. Anything but an Ed25519 PKCS#8 key is an
// error naming what it was.
func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("not a PEM file")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("a %s block, want a PKCS#8 PRIVATE KEY", block.Type)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("a %T, want an Ed25519 key", key)
	}
	return priv, nil
}
