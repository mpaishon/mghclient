package relayclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// GenerateKeyAndCSR makes a P-256 key on this machine and a certificate
// request for it. Only the request leaves the machine; the relay chooses the
// certificate's subject itself and ignores the one asked for here.
func GenerateKeyAndCSR(cn string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("make a key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: cn},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("make a certificate request: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), nil
}

// Fingerprint is the SHA-256 of a certificate's DER, lower-case hex.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// NormalizeFingerprint is a fingerprint as compared: lower-case hex, without
// the colons or spaces it may be written with.
func NormalizeFingerprint(fp string) string {
	return strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.ToLower(strings.TrimSpace(fp)))
}

// FormatFingerprint groups a fingerprint in pairs for reading aloud and
// comparing by eye: ab:cd:ef….
func FormatFingerprint(fp string) string {
	fp = NormalizeFingerprint(fp)
	var b strings.Builder
	for i := 0; i < len(fp); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		end := min(i+2, len(fp))
		b.WriteString(fp[i:end])
	}
	return b.String()
}

// parseCertificate reads the first CERTIFICATE block of a PEM file.
func parseCertificate(data []byte) (*x509.Certificate, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("no certificate in PEM data")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}
