package relayclient

// Regression tests for the adversarial review's findings.

import (
	"context"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mpaishon/mghclient/internal/protocol"
	"github.com/mpaishon/mghclient/internal/relayclient/relaytest"
)

// After a renewal the very next request presents the new
// certificate. A kept-alive connection would carry the old one, which the
// relay supersedes once the new one is seen anywhere, and the request would
// be refused as if the client were revoked.
func TestRenewalDropsConnectionsCarryingTheOldCertificate(t *testing.T) {
	s := relaytest.New(t, fakeData())
	var mu sync.Mutex
	var serials []*big.Int
	next := s.Relay.Config.Handler
	s.Relay.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			mu.Lock()
			serials = append(serials, r.TLS.PeerCertificates[0].SerialNumber)
			mu.Unlock()
		}
		next.ServeHTTP(w, r)
	})
	dir, _ := enroll(t, s)
	c := newClient(t, dir)
	if _, err := c.WhoAmI(context.Background()); err != nil { // opens a connection with the first certificate
		t.Fatal(err)
	}
	if renewed, err := c.RenewIfDue(context.Background(), false, time.Now().Add(-time.Minute)); err != nil || !renewed {
		t.Fatalf("renewal: %v %v", renewed, err)
	}
	if _, err := c.WhoAmI(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	last := serials[len(serials)-1]
	if last.Cmp(c.Identity().Leaf().SerialNumber) != 0 {
		t.Fatalf("the request after the renewal presented certificate %v, not the new %v", last, c.Identity().Leaf().SerialNumber)
	}
}

// Ping is a real authenticated request on a new connection, so
// a revoked client fails it — even with a kept-alive connection from before
// the revocation — with ErrRefused, which says why.
func TestPingFailsForARevokedClient(t *testing.T) {
	s := relaytest.New(t, fakeData())
	dir, _ := enroll(t, s)
	c := newClient(t, dir)
	if _, err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping of an enrolled client: %v", err)
	}
	if !s.Seen("GET " + protocol.PathWhoAmI) {
		t.Error("Ping made no request")
	}
	if _, err := c.WhoAmI(context.Background()); err != nil { // a kept-alive connection
		t.Fatal(err)
	}
	s.Revoke()
	_, err := c.Ping(context.Background())
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("Ping of a revoked client: %v, want ErrRefused", err)
	}
	if !strings.Contains(err.Error(), "revoked") || !strings.Contains(err.Error(), "not enrolled") {
		t.Errorf("the message does not say why: %v", err)
	}
}
