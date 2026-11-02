package relayclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"

	"github.com/sirupsen/logrus"
)

// Identity is this client's key and certificate, and the relay CA they are
// checked against. Renewal swaps the pair in place, so connections made after
// it present the new certificate without the client being rebuilt.
type Identity struct {
	paths Paths
	ca    *x509.Certificate
	pool  *x509.CertPool

	mu   sync.RWMutex
	pair tls.Certificate
}

// LoadIdentity reads the key, certificate and CA from the state folder. A
// renewal that was interrupted between writing the new pair and installing it
// is finished first (renew.go explains the order), so a crash never costs the
// enrolment.
func LoadIdentity(p Paths) (*Identity, error) {
	if err := finishRenewal(p); err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(p.CA())
	if err != nil {
		return nil, fmt.Errorf("read the relay CA: %w", err)
	}
	ca, err := parseCertificate(caPEM)
	if err != nil || !ca.IsCA {
		return nil, fmt.Errorf("%s holds no CA certificate", p.CA())
	}
	pair, err := tls.LoadX509KeyPair(p.Cert(), p.Key())
	if err != nil {
		return nil, fmt.Errorf("load the client certificate: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	id := &Identity{paths: p, ca: ca, pool: pool, pair: pair}
	if err := id.check(pair.Leaf); err != nil {
		return nil, err
	}
	return id, nil
}

// check verifies a client certificate against the relay CA, for client
// authentication.
func (id *Identity) check(leaf *x509.Certificate) error {
	if leaf == nil {
		return errors.New("no client certificate")
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:       id.pool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime: leaf.NotBefore, // expiry is reported separately, with its date
	})
	if err != nil {
		return fmt.Errorf("the client certificate does not chain to the relay CA: %w", err)
	}
	return nil
}

// Leaf is the current client certificate.
func (id *Identity) Leaf() *x509.Certificate {
	id.mu.RLock()
	defer id.mu.RUnlock()
	return id.pair.Leaf
}

// CA is the relay CA certificate.
func (id *Identity) CA() *x509.Certificate { return id.ca }

// Pool is the relay CA as a pool: the only roots a relay connection trusts.
func (id *Identity) Pool() *x509.CertPool { return id.pool }

// certificate is the tls.Config hook: whatever pair is current when a
// connection is made.
func (id *Identity) certificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	id.mu.RLock()
	defer id.mu.RUnlock()
	pair := id.pair
	return &pair, nil
}

func (id *Identity) set(pair tls.Certificate) {
	id.mu.Lock()
	id.pair = pair
	id.mu.Unlock()
}

// finishRenewal completes a renewal a crash interrupted. Renewal writes
// client.key.next and client.crt.next in full, keeps the current pair as
// .prev, then renames key.next over the key and crt.next over the
// certificate. So on disk there are three interrupted shapes:
//
//   - both .next files: nothing was installed yet. If they are a pair they
//     are installed now; if not (the certificate write never finished) they
//     are dropped and the current pair stands.
//   - only client.crt.next: the key was installed, the certificate not. The
//     new key pairs with crt.next, so it is installed.
//   - only client.key.next: the certificate never arrived; it is dropped.
func finishRenewal(p Paths) error {
	keyNext, certNext := p.Key()+nextSuffix, p.Cert()+nextSuffix
	hasKey, hasCert := exists(keyNext), exists(certNext)
	switch {
	case hasKey && hasCert:
		if _, err := tls.LoadX509KeyPair(certNext, keyNext); err != nil {
			logrus.WithError(err).Warn("relay: dropping an unfinished certificate renewal")
			_ = os.Remove(keyNext)
			_ = os.Remove(certNext)
			return nil
		}
		if err := rename(keyNext, p.Key()); err != nil {
			return fmt.Errorf("finish the interrupted renewal (key): %w", err)
		}
		if err := rename(certNext, p.Cert()); err != nil {
			return fmt.Errorf("finish the interrupted renewal (certificate): %w", err)
		}
		logrus.Info("relay: finished a certificate renewal that was interrupted")
	case hasCert:
		if _, err := tls.LoadX509KeyPair(certNext, p.Key()); err != nil {
			// The key on disk is the old one: crt.next belongs to a key that
			// was never installed. Keep what pairs.
			logrus.WithError(err).Warn("relay: dropping a renewed certificate whose key was lost")
			_ = os.Remove(certNext)
			return nil
		}
		if err := rename(certNext, p.Cert()); err != nil {
			return fmt.Errorf("finish the interrupted renewal (certificate): %w", err)
		}
		logrus.Info("relay: finished a certificate renewal that was interrupted")
	case hasKey:
		_ = os.Remove(keyNext)
	}
	return nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, fs.ErrNotExist)
}
