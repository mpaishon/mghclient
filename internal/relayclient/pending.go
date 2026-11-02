package relayclient

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mpaishon/mghclient/internal/protocol"
)

// Approval enrolment on the client side. The
// request is answered with a poll token; the key whose CSR was sent is the
// one that will be signed, so it and the token are kept in the state
// folder (0600) until the request is decided, and a restart resumes the
// wait instead of asking again. Neither file makes the folder "enrolled":
// Paths.Enrolled looks at the key, certificate and state only.

// The pending enrolment's files.
const (
	PendingFile    = "pending.json"
	PendingKeyFile = "pending.key"
)

func (p Paths) Pending() string    { return filepath.Join(p.Dir, PendingFile) }
func (p Paths) PendingKey() string { return filepath.Join(p.Dir, PendingKeyFile) }

// Pending is an enrolment request waiting for approval.
type Pending struct {
	App    string `json:"app"`
	WebURL string `json:"web_url"`
	// Token is the poll token, a secret: whoever holds it collects the
	// certificate once approved (only with the key, which never leaves).
	Token          string `json:"token"`
	WebFingerprint string `json:"web_fingerprint,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	// Pairing names the key the request is for (e.g. "K3QZ-7MDA"): show it
	// to the user, who checks the console shows the same beside the request
	// before approving it.
	Pairing     string    `json:"pairing,omitempty"`
	PollEvery   int       `json:"poll_every"`
	ExpiresAt   time.Time `json:"expires_at"`
	RequestedAt time.Time `json:"requested_at"`
}

// Errors of approval enrolment.
var (
	// ErrPending is a request made and waiting (EnrollOptions.NoWait).
	ErrPending = errors.New("the enrolment request is waiting for approval on the relay's console")
	// ErrDenied is a request the relay did not approve: denied, or not
	// decided in time. The relay does not say which (UG-12).
	ErrDenied = errors.New("the enrolment request was not approved by the relay administrator")
)

// ticketUnknown is the relay's text for a poll token it does not hold
// (enroll.ErrTicketUnknown), as opposed to its bare "Not found".
const ticketUnknown = "no such enrolment request"

// PairingCode names a key the way the relay names the request it was sent
// with (enroll.Pairing): the first 8 base32 characters of the SHA-256 of
// its public key, as XXXX-XXXX.
func PairingCode(keyPEM []byte) string {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return ""
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return ""
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return ""
	}
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(spki)
	code := base32.StdEncoding.EncodeToString(sum[:])[:8]
	return code[:4] + "-" + code[4:]
}

// slowPollAfter is when polling slows to maxPoll (§8.2: back off after an
// hour).
const (
	slowPollAfter = time.Hour
	minPoll       = 5 * time.Second
	maxPoll       = 5 * time.Minute
)

// LoadPending reads a pending enrolment; nil when there is none.
func LoadPending(p Paths) (*Pending, error) {
	raw, err := os.ReadFile(p.Pending())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var pend Pending
	if err := json.Unmarshal(raw, &pend); err != nil || pend.Token == "" {
		return nil, fmt.Errorf("%s is unreadable; delete it to ask again", p.Pending())
	}
	if _, err := os.Stat(p.PendingKey()); err != nil {
		return nil, fmt.Errorf("%s has no key beside it; delete it to ask again", p.Pending())
	}
	return &pend, nil
}

// ClearPending removes a pending enrolment.
func ClearPending(p Paths) {
	_ = os.Remove(p.Pending())
	_ = os.Remove(p.PendingKey())
}

func savePending(p Paths, pend *Pending, keyPEM []byte) error {
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return fmt.Errorf("create the relay state folder: %w", err)
	}
	if err := hardenState(p); err != nil {
		return fmt.Errorf("make the relay state folder private: %w", err)
	}
	if err := writeFile(p.PendingKey(), keyPEM, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", p.PendingKey(), err)
	}
	raw, err := json.MarshalIndent(pend, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFile(p.Pending(), raw, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", p.Pending(), err)
	}
	return hardenState(p)
}

// resume picks a pending enrolment up again: the same relay (its URL and
// the web certificate accepted when it was made), the same key.
func resume(ctx context.Context, o EnrollOptions, paths Paths, pend *Pending) (*EnrollResult, error) {
	if pend.App != o.App {
		return nil, fmt.Errorf("a request to enrol as %q is already waiting in %s; enrol with --force to replace it", pend.App, paths.Dir)
	}
	keyPEM, err := os.ReadFile(paths.PendingKey())
	if err != nil {
		return nil, err
	}
	o.URL = pend.WebURL
	if o.Hostname == "" {
		o.Hostname = pend.Hostname
	}
	if pend.WebFingerprint != "" {
		o.AcceptFingerprint, o.Confirm = pend.WebFingerprint, nil
	}
	tlsCfg, probe, err := webTrust(ctx, o)
	if err != nil {
		return nil, err
	}
	if o.OnPending != nil {
		o.OnPending(*pend)
	}
	if o.NoWait {
		// One poll, so a caller that does not wait still learns a decision.
		res, done, err := pollOnce(ctx, o, paths, pend, keyPEM, webClient(tlsCfg), probe)
		if done || err != nil {
			return res, err
		}
		return nil, ErrPending
	}
	return wait(ctx, o, paths, pend, keyPEM, webClient(tlsCfg), probe)
}

// pollInterval is how long to wait before the next poll.
func pollInterval(pend *Pending, now time.Time) time.Duration {
	every := time.Duration(pend.PollEvery) * time.Second
	if every < minPoll {
		every = time.Duration(protocol.TicketPollEvery) * time.Second
	}
	if !pend.RequestedAt.IsZero() && now.Sub(pend.RequestedAt) > slowPollAfter {
		every = maxPoll
	}
	return min(every, maxPoll)
}

// wait polls until the request is decided or ctx ends.
func wait(ctx context.Context, o EnrollOptions, paths Paths, pend *Pending, keyPEM []byte, client *http.Client, probe Probe) (*EnrollResult, error) {
	for {
		res, done, err := pollOnce(ctx, o, paths, pend, keyPEM, client, probe)
		if done || err != nil {
			return res, err
		}
		if !pend.ExpiresAt.IsZero() && time.Now().After(pend.ExpiresAt.Add(time.Minute)) {
			ClearPending(paths)
			return nil, ErrDenied
		}
		t := time.NewTimer(pollInterval(pend, time.Now()))
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

// pollOnce asks once. done is a decision (res or a terminal error); a
// still-pending request or a poll that failed in transit is neither.
func pollOnce(ctx context.Context, o EnrollOptions, paths Paths, pend *Pending, keyPEM []byte, client *http.Client, probe Probe) (res *EnrollResult, done bool, err error) {
	u := "https://" + probe.Addr + protocol.PathEnrollTicket + url.PathEscape(pend.Token)
	status, raw, retry, err := webCall(ctx, client, http.MethodGet, u, nil, o.userAgent())
	if err != nil {
		if ctx.Err() != nil {
			return nil, true, ctx.Err()
		}
		if o.OnPoll != nil {
			o.OnPoll(*pend, err)
		}
		return nil, false, nil
	}
	switch status {
	case http.StatusOK:
	case http.StatusGone:
		ClearPending(paths)
		return nil, true, errors.New("the relay says this enrolment was collected already, but this machine has no certificate from it; enrol again")
	case http.StatusNotFound:
		if errorText(raw) != ticketUnknown {
			// The bare 404 of enrolment closed to this address (a laptop
			// that roamed outside): the request may well be approved, so
			// keep the key and try again later.
			if o.OnPoll != nil {
				o.OnPoll(*pend, errors.New("the relay's enrolment is not reachable from this network; still waiting"))
			}
			return nil, false, nil
		}
		ClearPending(paths)
		return nil, true, errors.New("the relay no longer knows this enrolment request; enrol again")
	case http.StatusTooManyRequests:
		if retry > 0 {
			pend.PollEvery = max(pend.PollEvery, retry)
		}
		if o.OnPoll != nil {
			o.OnPoll(*pend, errors.New("the relay is rate-limiting this address"))
		}
		return nil, false, nil
	default:
		if o.OnPoll != nil {
			o.OnPoll(*pend, fmt.Errorf("HTTP %d %s", status, errorText(raw)))
		}
		return nil, false, nil
	}
	var t protocol.EnrollTicket
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, false, nil
	}
	if t.PollEvery > 0 {
		pend.PollEvery = t.PollEvery
	}
	switch t.State {
	case protocol.TicketPending:
		if o.OnPoll != nil {
			o.OnPoll(*pend, nil)
		}
		return nil, false, nil
	case protocol.TicketApproved:
		if t.Enrolled == nil {
			return nil, true, errors.New("the relay approved the enrolment but sent no certificate")
		}
		o.URL = pend.WebURL
		if o.Hostname == "" {
			o.Hostname = pend.Hostname
		}
		res, err := keep(o, paths, probe, keyPEM, *t.Enrolled)
		if err != nil {
			return nil, true, err
		}
		ClearPending(paths)
		return res, true, nil
	default:
		ClearPending(paths)
		return nil, true, ErrDenied
	}
}

// PendingText is a line for a person about a pending enrolment.
func PendingText(p Pending) string {
	var b strings.Builder
	fmt.Fprintf(&b, "waiting for approval on the relay's console (Apps → %s → Instances)", p.App)
	if p.Pairing != "" {
		fmt.Fprintf(&b, "; approve the request showing %s", p.Pairing)
	}
	if !p.ExpiresAt.IsZero() {
		fmt.Fprintf(&b, "; the request lapses %s", p.ExpiresAt.Local().Format("Mon 2 Jan 15:04"))
	}
	return b.String()
}
