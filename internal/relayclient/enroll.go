package relayclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mpaishon/mghclient/internal/protocol"
)

// Enrolment: a key is
// made here, only a CSR and the one-time code go to the relay's web listener,
// and what comes back — the certificate, the CA that is the only trust for
// every later connection, and where the mutual-TLS listener is — is checked
// before any of it is kept.

// callTimeout bounds one request to the relay.
const callTimeout = 30 * time.Second

// maxReply bounds a JSON reply from the relay.
const maxReply = 32 << 20

// EnrollOptions is one enrolment.
type EnrollOptions struct {
	// URL is the relay's web listener, https://host[:port], as the operator
	// was given it (the port defaults to 443, for a proxy in front).
	URL  string
	Code string // the one-time code from the console's Clients page

	// AcceptFingerprint is the SHA-256 of the web listener's certificate the
	// operator has checked. It is needed when that certificate does not chain
	// to the system's roots (a self-signed one): trust on first use.
	AcceptFingerprint string
	// Confirm, when set, is asked instead (a typed yes at a terminal).
	Confirm func(fingerprint string) (bool, error)

	StateDir string
	// Force enrols over an existing enrolment in StateDir.
	Force bool

	// Roots are the roots a web certificate may chain to; nil is the
	// system's.
	Roots *x509.CertPool

	// Hostname is what this machine calls itself (default: os.Hostname).
	Hostname string
	// Version is this build, sent so the console can show it.
	Version string

	// App is the app this client is an instance of (docs/UPGRADE_GATEWAY.md):
	// sent with a code, and without one it asks for approval. Empty is the
	// code's app (the relay's own client).
	App string
	// OnPending is told once when a request without a code is waiting for
	// approval (and again when a pending one is resumed).
	OnPending func(Pending)
	// OnPoll, when set, is told each time a pending request is still
	// pending, and of a poll that failed (err set; polling goes on).
	OnPoll func(Pending, error)
	// NoWait returns ErrPending once the request is made, instead of
	// polling; the next Enroll resumes it.
	NoWait bool
	// Product names the client in the User-Agent; empty is mghagent.
	Product string
}

func (o EnrollOptions) userAgent() string { return userAgentFor(o.Product, o.Version, "") }

// EnrollResult is what the relay answered.
type EnrollResult struct {
	ClientID       string
	Profile        string
	CAFingerprint  string
	WebFingerprint string // empty when the web certificate chained to the system roots
	RelayURL       string
	Names          []string // the names on the relay listener's certificate
	PublicURL      string   // r2-C: the public address the relay advertised; "" for none
	NotAfter       time.Time
}

// HostInNames reports whether the relay host this client will use is on the
// relay listener's certificate; if not, every relay connection will fail
// verification and the operator should be told now.
func (r EnrollResult) HostInNames(host string) bool {
	return slices.ContainsFunc(r.Names, func(n string) bool { return strings.EqualFold(n, host) })
}

// ErrAlreadyEnrolled is a state folder that already holds an enrolment.
var ErrAlreadyEnrolled = errors.New("this machine is already enrolled (its relay state folder holds a key, certificate or state); pass --force to enrol again")

// FingerprintError is a web certificate the client has not been told to
// trust.
type FingerprintError struct {
	Host        string
	Fingerprint string
	Mismatch    bool // --accept-fingerprint was given and differs
}

func (e *FingerprintError) Error() string {
	if e.Mismatch {
		return fmt.Sprintf("the relay at %s presented a certificate with SHA-256 fingerprint\n  %s\n"+
			"which is not the fingerprint given with --accept-fingerprint. Nothing was sent. "+
			"Check which machine answers at that address before trying again.", e.Host, FormatFingerprint(e.Fingerprint))
	}
	return fmt.Sprintf("the relay at %s presented a certificate that this machine does not trust "+
		"(self-signed, as a fresh install's is). Its SHA-256 fingerprint is\n  %s\n"+
		"Compare it with the one the relay's console shows (Clients → Enrolment codes), "+
		"then run again with --accept-fingerprint %s", e.Host, FormatFingerprint(e.Fingerprint), e.Fingerprint)
}

// WebAddress parses an enrolment URL: https only (the code and the CSR must
// not travel in the clear), host[:port], no path, query or credentials.
func WebAddress(raw string) (host, addr string, err error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", "", fmt.Errorf("%q is not a URL like https://relay.example.com:8444", raw)
	}
	if u.Scheme != "https" {
		return "", "", fmt.Errorf("%q must be https: the code and the certificate request must not travel in the clear", raw)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil || u.Fragment != "" {
		return "", "", fmt.Errorf("%q must be only https://host[:port], without a path", raw)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if n, err := strconv.Atoi(port); err != nil || n <= 0 || n > 65535 {
		return "", "", fmt.Errorf("%q has no valid port", raw)
	}
	return u.Hostname(), net.JoinHostPort(u.Hostname(), port), nil
}

// Probe is what the web listener presented.
type Probe struct {
	Host, Addr  string
	Fingerprint string // SHA-256 of its leaf certificate, hex
	Trusted     bool   // it chains to the roots (the system's when nil)
}

// ProbeWeb reads the web listener's certificate without sending anything,
// so a person can be shown its fingerprint before agreeing to trust it.
func ProbeWeb(ctx context.Context, rawURL string, roots *x509.CertPool) (Probe, error) {
	host, addr, err := WebAddress(rawURL)
	if err != nil {
		return Probe{}, err
	}
	probe := &tls.Config{InsecureSkipVerify: true, ServerName: host, MinVersion: tls.VersionTLS12} //nolint:gosec // only to read the certificate; nothing is sent
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: probe}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return Probe{}, fmt.Errorf("reach the relay at %s: %w", addr, err)
	}
	state := conn.(*tls.Conn).ConnectionState()
	_ = conn.Close()
	if len(state.PeerCertificates) == 0 {
		return Probe{}, fmt.Errorf("the relay at %s presented no certificate", addr)
	}
	leaf := state.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: inter})
	return Probe{Host: host, Addr: addr, Fingerprint: Fingerprint(leaf), Trusted: verr == nil}, nil
}

// webTrust decides how the web listener is trusted: through the system roots
// when its certificate chains to them, otherwise by the operator accepting
// its fingerprint. The TLS config it returns is pinned to the very
// certificate that was accepted.
func webTrust(ctx context.Context, o EnrollOptions) (*tls.Config, Probe, error) {
	p, err := ProbeWeb(ctx, o.URL, o.Roots)
	if err != nil {
		return nil, p, err
	}
	if p.Trusted {
		return &tls.Config{ServerName: p.Host, RootCAs: o.Roots, MinVersion: tls.VersionTLS12}, p, nil
	}
	switch {
	case o.AcceptFingerprint != "":
		if NormalizeFingerprint(o.AcceptFingerprint) != p.Fingerprint {
			return nil, p, &FingerprintError{Host: p.Addr, Fingerprint: p.Fingerprint, Mismatch: true}
		}
	case o.Confirm != nil:
		ok, err := o.Confirm(p.Fingerprint)
		if err != nil {
			return nil, p, err
		}
		if !ok {
			return nil, p, &FingerprintError{Host: p.Addr, Fingerprint: p.Fingerprint}
		}
	default:
		return nil, p, &FingerprintError{Host: p.Addr, Fingerprint: p.Fingerprint}
	}
	fp := p.Fingerprint
	pinned := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // verified by VerifyConnection against the accepted fingerprint
		ServerName:         p.Host,
		MinVersion:         tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || Fingerprint(cs.PeerCertificates[0]) != fp {
				return errors.New("the relay's certificate changed after it was accepted")
			}
			return nil
		},
	}
	return pinned, p, nil
}

// Enroll makes a key here, sends only a CSR and the code to the relay's
// enrolment route, and keeps what comes back. The key is written first, with
// 0600, and the state file last: a state file means a complete enrolment.
//
// Without a code, and with App set, it asks the relay for approval instead
// (docs/UPGRADE_GATEWAY.md §8.2): the key and the poll token are kept in the
// state folder as a pending enrolment (both 0600), and Enroll polls until
// the request is approved (the enrolment is then kept as with a code),
// denied (ErrDenied) or ctx ends (the pending enrolment stays, and the next
// Enroll resumes it). NoWait returns ErrPending after the request is made.
// An app whose relay auto-approves the local network enrols at once.
func Enroll(ctx context.Context, o EnrollOptions) (*EnrollResult, error) {
	o.Code = strings.TrimSpace(o.Code)
	o.App = strings.ToLower(strings.TrimSpace(o.App))
	if o.StateDir == "" {
		return nil, errors.New("no relay state folder configured")
	}
	paths := Paths{Dir: o.StateDir}
	if paths.Enrolled() && !o.Force {
		return nil, ErrAlreadyEnrolled
	}
	if o.Code == "" && o.App != "" {
		if pend, err := LoadPending(paths); err == nil && pend != nil && !o.Force {
			return resume(ctx, o, paths, pend)
		}
	}
	if o.Force {
		ClearPending(paths)
	}
	if strings.TrimSpace(o.URL) == "" || (o.Code == "" && o.App == "") {
		return nil, errors.New("an enrolment needs the relay's URL and a one-time code (or the app, to ask for approval)")
	}
	if o.Hostname == "" {
		o.Hostname, _ = os.Hostname()
	}
	tlsCfg, probe, err := webTrust(ctx, o)
	if err != nil {
		return nil, err
	}

	keyPEM, csrPEM, err := GenerateKeyAndCSR(o.Hostname)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(protocol.EnrollRequest{
		App: o.App, Code: o.Code, CSRPEM: string(csrPEM), Hostname: o.Hostname,
		OS: runtime.GOOS, Arch: runtime.GOARCH, Version: o.Version,
	})
	if err != nil {
		return nil, err
	}
	client := webClient(tlsCfg)
	status, raw, _, err := webCall(ctx, client, http.MethodPost, "https://"+probe.Addr+protocol.PathEnroll, body, o.userAgent())
	if err != nil {
		return nil, fmt.Errorf("enrol at %s: %w", probe.Addr, err)
	}
	switch status {
	case http.StatusCreated, http.StatusOK:
	case http.StatusAccepted:
		var t protocol.EnrollTicket
		if err := json.Unmarshal(raw, &t); err != nil || t.Ticket == "" {
			return nil, errors.New("unreadable enrolment request reply")
		}
		pend := &Pending{
			App: o.App, WebURL: strings.TrimRight(strings.TrimSpace(o.URL), "/"), Token: t.Ticket, Hostname: o.Hostname,
			PollEvery: t.PollEvery, ExpiresAt: t.ExpiresAt.UTC(), RequestedAt: time.Now().UTC(),
			Pairing: PairingCode(keyPEM),
		}
		if !probe.Trusted {
			pend.WebFingerprint = probe.Fingerprint
		}
		if err := savePending(paths, pend, keyPEM); err != nil {
			return nil, err
		}
		if o.OnPending != nil {
			o.OnPending(*pend)
		}
		if o.NoWait {
			return nil, ErrPending
		}
		return wait(ctx, o, paths, pend, keyPEM, client, probe)
	case http.StatusUnauthorized:
		if o.Code == "" {
			return nil, errors.New("the relay does not take enrolment requests for this app without a code: it may not exist, be disabled, take codes only, or have too many requests waiting — ask for a code")
		}
		return nil, errors.New("the relay did not accept the code: it may be mistyped, used already, expired or revoked — ask for a new one on the console's Clients page")
	case http.StatusTooManyRequests:
		return nil, errors.New("too many failed enrolments from this address; wait and try again")
	case http.StatusNotFound:
		return nil, fmt.Errorf("%s has no enrolment route: is it an mghRelay, and is enrolment open to this address?", probe.Addr)
	default:
		return nil, fmt.Errorf("enrolment refused: HTTP %d %s", status, errorText(raw))
	}
	var reply protocol.EnrollResponse
	if err := json.Unmarshal(raw, &reply); err != nil {
		return nil, fmt.Errorf("unreadable enrolment reply: %w", err)
	}
	res, err := keep(o, paths, probe, keyPEM, reply)
	if err == nil {
		ClearPending(paths) // a code (or LAN approval) settles any request left waiting
	}
	return res, err
}

// keep checks an enrolment reply and, only if all of it holds, writes the
// key (first, 0600), the certificate, the CA and the state file (last).
func keep(o EnrollOptions, paths Paths, probe Probe, keyPEM []byte, reply protocol.EnrollResponse) (*EnrollResult, error) {
	// Check what came back before keeping any of it.
	ca, err := parseCertificate([]byte(reply.CAPEM))
	if err != nil || !ca.IsCA {
		return nil, errors.New("the enrolment reply carries no CA certificate")
	}
	caFP := Fingerprint(ca)
	if reply.CAFingerprint != "" && caFP != NormalizeFingerprint(reply.CAFingerprint) {
		return nil, errors.New("the enrolment reply's CA fingerprint does not match its CA certificate")
	}
	pair, err := tls.X509KeyPair([]byte(reply.CertPEM), keyPEM)
	if err != nil {
		return nil, fmt.Errorf("the issued certificate is not for the key made here: %w", err)
	}
	if reply.ClientID == "" || pair.Leaf.Subject.CommonName != reply.ClientID {
		return nil, errors.New("the issued certificate does not name the client id the relay gave")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := pair.Leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, fmt.Errorf("the issued certificate does not chain to the CA it came with: %w", err)
	}
	port, err := strconv.Atoi(reply.Relay.Port)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("the enrolment reply has no relay port (%q)", reply.Relay.Port)
	}
	relayURL := "https://" + net.JoinHostPort(probe.Host, strconv.Itoa(port))

	// Keep it: the key first (0600), the state last.
	if err := os.MkdirAll(paths.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("create the relay state folder: %w", err)
	}
	// Private before the key is written, so the key is never readable by
	// others even for a moment (SR-12; Windows, where the modes do nothing).
	if err := hardenState(paths); err != nil {
		return nil, fmt.Errorf("make the relay state folder private: %w", err)
	}
	for _, stale := range []string{paths.State(), paths.Key() + nextSuffix, paths.Cert() + nextSuffix, paths.Key() + prevSuffix, paths.Cert() + prevSuffix} {
		_ = os.Remove(stale)
	}
	for _, f := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{paths.Key(), keyPEM, 0o600},
		{paths.Cert(), []byte(reply.CertPEM), 0o644},
		{paths.CA(), []byte(reply.CAPEM), 0o644},
	} {
		if err := writeFile(f.path, f.data, f.mode); err != nil {
			return nil, fmt.Errorf("write %s: %w", f.path, err)
		}
	}
	st := &State{
		ClientID: reply.ClientID, Profile: reply.Profile, Hostname: o.Hostname,
		RelayURL: relayURL, WebURL: strings.TrimRight(strings.TrimSpace(o.URL), "/"),
		CAFingerprint: caFP, RelayNames: reply.Relay.Names,
		InternalURL: endpointURL(reply.Relay.Internal), PublicURL: endpointURL(reply.Relay.Public), // r2-C
		Profiles:   reply.Relay.Profiles, // N2
		EnrolledAt: time.Now().UTC(), NotAfter: pair.Leaf.NotAfter.UTC(),
		App: o.App,
	}
	// N4: the install line chose this machine's connection profile.
	if c := reply.Conn; c != nil && c.Managed {
		st.ConnProfile, st.ConnNoFallback, st.ConnRev = c.Profile, c.NoFallback && c.Profile != "", c.Rev
		if c.Locked {
			st.ConnLockedBy = "console"
		}
	}
	if !probe.Trusted {
		st.WebFingerprint = probe.Fingerprint
	}
	if err := SaveState(paths, st); err != nil {
		return nil, err
	}
	if err := hardenState(paths); err != nil {
		return nil, fmt.Errorf("make the relay state private: %w", err)
	}
	return &EnrollResult{
		ClientID: reply.ClientID, Profile: reply.Profile, CAFingerprint: caFP,
		WebFingerprint: st.WebFingerprint, RelayURL: relayURL, Names: reply.Relay.Names,
		NotAfter: pair.Leaf.NotAfter, PublicURL: st.PublicURL,
	}, nil
}

func webClient(cfg *tls.Config) *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: cfg, TLSHandshakeTimeout: 10 * time.Second}}
}

// webCall makes one request to the web listener: its status, its body (at
// most 1 MiB) and its Retry-After in seconds.
func webCall(ctx context.Context, client *http.Client, method, u string, body []byte, ua string) (int, []byte, int, error) {
	reqCtx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(reqCtx, method, u, rd)
	if err != nil {
		return 0, nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	retry, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
	return resp.StatusCode, raw, retry, nil
}

// errorText is the relay's {"error": "..."} text, or nothing.
func errorText(raw []byte) string {
	var e protocol.Error
	if json.Unmarshal(raw, &e) == nil {
		return e.Error
	}
	return ""
}

// userAgent is what every request says about this client:
// mghagent/<version> (<goos>-<arch>; update=<state>). The relay records the
// version and the update state from it.
func userAgent(version, update string) string { return userAgentFor("", version, update) }

// userAgentFor is userAgent for another product (an app instance): the
// relay records versions only from mghagent's, so an app's is never taken
// for an agent's; an app reports its version itself.
func userAgentFor(product, version, update string) string {
	if product == "" {
		product = "mghagent"
	}
	if version == "" {
		version = "dev"
	}
	if update == "" {
		update = "none"
	}
	return fmt.Sprintf("%s/%s (%s-%s; update=%s)", product, version, runtime.GOOS, runtime.GOARCH, update)
}
