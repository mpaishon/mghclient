package relayclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/mpaishon/mghclient/internal/protocol"
)

// Renewal. The relay
// renews a client certificate from 30 days before it expires and says
// when in /whoami (renew_after); without that word the client falls back to
// the same rule itself.

// maxRenewLead is how early renewal starts without the relay's word: 30
// days before expiry, capped at half the certificate's lifetime so a
// short-lived certificate is not renewed on every start.
const maxRenewLead = 30 * 24 * time.Hour

// RenewDue reports whether leaf should be renewed at now. renewAfter is the
// relay's word (zero when unknown).
func RenewDue(leaf *x509.Certificate, now, renewAfter time.Time) bool {
	if !renewAfter.IsZero() {
		return !now.Before(renewAfter)
	}
	lead := min(leaf.NotAfter.Sub(leaf.NotBefore)/2, maxRenewLead)
	return !now.Before(leaf.NotAfter.Add(-lead))
}

// ErrRevoked is a renewal the relay refused because the client is no longer
// enrolled.
var ErrRevoked = errors.New("the relay refused to renew this client's certificate: it has been revoked; enrol again with a new code")

// RenewIfDue renews the certificate when it is in its renewal window, or
// always when force is set (--renew-now). It reports whether the certificate
// was replaced.
func (c *Client) RenewIfDue(ctx context.Context, force bool, renewAfter time.Time) (bool, error) {
	if !force && !RenewDue(c.id.Leaf(), time.Now(), renewAfter) {
		return false, nil
	}
	logrus.WithField("not_after", c.id.Leaf().NotAfter.UTC().Format(time.RFC3339)).Info("relay: renewing the client certificate")
	return true, c.Renew(ctx)
}

// Renew asks the relay for a new certificate for a new key. The key is made
// here and only its CSR is sent, over mutual TLS with the current
// certificate. Both new files are written in full first (.next), the pair
// being replaced is kept as .prev, and then the new key and the new
// certificate are renamed into place in that order. A crash at any point
// leaves a state LoadIdentity finishes (finishRenewal).
func (c *Client) Renew(ctx context.Context) error {
	clientID := c.State().ClientID
	keyPEM, csrPEM, err := GenerateKeyAndCSR(clientID)
	if err != nil {
		return err
	}
	body, err := json.Marshal(protocol.RenewRequest{CSRPEM: string(csrPEM)})
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	resp, err := c.do(rctx, http.MethodPost, protocol.PathRenew, nil, bytes.NewReader(body))
	if err != nil {
		if code := StatusOf(err); code == http.StatusForbidden || code == http.StatusUnauthorized {
			return ErrRevoked
		}
		return fmt.Errorf("renewal: %w", err)
	}
	var reply protocol.RenewResponse
	err = decode(resp.Body, &reply)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("renewal: unreadable reply: %w", err)
	}
	pair, err := tls.X509KeyPair([]byte(reply.CertPEM), keyPEM)
	if err != nil {
		return fmt.Errorf("the renewed certificate is not for the key made here: %w", err)
	}
	if pair.Leaf.Subject.CommonName != clientID {
		return fmt.Errorf("the renewed certificate names client %q, not %q", pair.Leaf.Subject.CommonName, clientID)
	}
	if err := c.id.check(pair.Leaf); err != nil {
		return err
	}
	// The new key goes into a private folder, and every file is
	// private again once it is in place.
	if err := hardenState(c.paths); err != nil {
		return fmt.Errorf("renewal: make the relay state folder private: %w", err)
	}
	if err := installRenewal(c.paths, keyPEM, []byte(reply.CertPEM), renewInterrupt); err != nil {
		return err
	}
	if err := hardenState(c.paths); err != nil {
		// The pair is installed; the next load refuses it until the folder
		// can be made private.
		logrus.WithError(err).Error("relay: the renewed key is installed but could not be made private")
	}
	c.id.set(pair)
	// A kept-alive connection still carries the old certificate, which the
	// relay supersedes as soon as the new one is presented anywhere (another
	// mghagent process on this machine, say); its next request would then be
	// refused as if this client were revoked. New connections present the
	// new certificate.
	c.httpc.CloseIdleConnections()

	c.stateM.Lock()
	now := time.Now().UTC()
	st := *c.state
	st.NotAfter, st.RenewedAt = pair.Leaf.NotAfter.UTC(), &now
	err = SaveState(c.paths, &st)
	if err == nil {
		c.state = &st
	}
	c.stateM.Unlock()
	if err != nil {
		// The new pair is installed and works; only the record of its date
		// is stale, and /whoami reports the real one.
		logrus.WithError(err).Warn("relay: the renewed certificate is installed but state.json could not be updated")
	}
	logrus.WithField("not_after", pair.Leaf.NotAfter.UTC().Format(time.RFC3339)).Info("relay: client certificate renewed")
	return nil
}

// renewStep names the points of an installation, so a test can stop it
// where a crash could.
type renewStep int

const (
	stepNextWritten  renewStep = iota // both .next files are complete
	stepKeyInstalled                  // the new key is in place, the certificate not yet
)

// renewInterrupt is consulted at each step; a non-nil error stops the
// installation there, as a crash would. Only tests set it.
var renewInterrupt = func(renewStep) error { return nil }

func installRenewal(p Paths, keyPEM, certPEM []byte, interrupt func(renewStep) error) error {
	if err := writeFile(p.Key()+nextSuffix, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write the renewed key: %w", err)
	}
	if err := writeFile(p.Cert()+nextSuffix, certPEM, 0o644); err != nil {
		return fmt.Errorf("write the renewed certificate: %w", err)
	}
	// One generation of the pair being replaced is kept, so an operator can
	// see what was there; it is never used to connect.
	if old, err := os.ReadFile(p.Key()); err == nil {
		if err := writeFile(p.Key()+prevSuffix, old, 0o600); err != nil {
			logrus.WithError(err).Warn("relay: could not keep the previous key")
		}
	}
	if old, err := os.ReadFile(p.Cert()); err == nil {
		_ = writeFile(p.Cert()+prevSuffix, old, 0o644)
	}
	if err := interrupt(stepNextWritten); err != nil {
		return err
	}
	if err := rename(p.Key()+nextSuffix, p.Key()); err != nil {
		return fmt.Errorf("install the renewed key: %w", err)
	}
	if err := interrupt(stepKeyInstalled); err != nil {
		return err
	}
	if err := rename(p.Cert()+nextSuffix, p.Cert()); err != nil {
		return fmt.Errorf("install the renewed certificate: %w", err)
	}
	return nil
}
