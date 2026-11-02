// Package mghclient is the client SDK for an application that updates
// through an mghRelay. Import it as github.com/mpaishon/mghclient (the
// public module, README.md and ONBOARDING.md there); it is maintained in
// MyGHAgent's mghclient/ folder and exported (go run ./bld/sdkexport).
//
// An instance of an app enrols once — with a one-time code, or by asking
// and waiting for an administrator's approval — and from then on talks to
// the relay over mutual TLS with the certificate it was issued:
//
//	inst, err := mghclient.Enrol(ctx, cfg, mghclient.EnrolOptions{URL: "https://relay.home.lan:8444"})
//	...
//	offer, err := inst.Check(ctx)          // nil: nothing to install
//	err = inst.DownloadFile(ctx, offer, "/tmp/app.zip", nil)
//	reply, err := inst.Report(ctx, mghclient.Report{Version: v, UpdateState: mghclient.StateConfirmed})
//
// or hand the loop to Run. Installing, staging and restarting are the
// application's own business: the SDK finds, fetches and verifies.
//
// The SDK is the same code the relay's own client (mghagent) uses — the
// internal relayclient, protocol and releasekey packages — behind a small
// surface that keeps its compatibility promises.
package mghclient

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/mpaishon/mghclient/internal/protocol"
	"github.com/mpaishon/mghclient/internal/relayclient"
	"github.com/mpaishon/mghclient/internal/releasekey"
)

// The wire types, as the relay sends them.
type (
	// Offer is the relay's answer to "is there anything for me?".
	Offer = protocol.Offer
	// Release is one release of the app as the relay lists it.
	Release = protocol.Release
	// Report is what an instance tells the relay about itself.
	Report = protocol.InstanceReport
	// Reply answers a Report: when to check again, and the offer.
	Reply = protocol.InstanceReply
	// Pending is an enrolment request waiting for approval.
	Pending = relayclient.Pending
)

// Update states for Report.UpdateState, as the console shows them.
const (
	StateStaged     = protocol.UpdateStaged     // downloaded and verified, waiting to be applied
	StateSwapped    = protocol.UpdateSwapped    // applied, running the new version for the first time
	StateConfirmed  = protocol.UpdateConfirmed  // the new version is healthy
	StateRolledBack = protocol.UpdateRolledBack // the new version failed and the old one is back
	StateFailed     = protocol.UpdateFailed     // the update could not be applied
)

// Update policies an Offer carries (resolved by the relay: the instance's,
// else the app's, else the household's).
const (
	PolicyOff       = protocol.UpdateOff
	PolicyNotify    = protocol.UpdateNotify    // tell the user; install when they say
	PolicyAutomatic = protocol.UpdateAutomatic // install without asking
)

// Errors a caller tells apart.
var (
	// ErrNotEnrolled is a state folder with no enrolment.
	ErrNotEnrolled = errors.New("mghclient: not enrolled with a relay")
	// ErrPending is an enrolment request waiting for approval
	// (EnrolOptions.NoWait). Enrol again later to resume it.
	ErrPending = relayclient.ErrPending
	// ErrDenied is an enrolment request that was not approved (denied, or
	// not decided in time; the relay does not say which).
	ErrDenied = relayclient.ErrDenied
	// ErrRevoked is the relay refusing this instance's certificate: it was
	// revoked or deleted. Enrol again.
	ErrRevoked = errors.New("mghclient: the relay refused this instance's certificate (revoked or not enrolled); enrol again")
	// ErrBadSignature is a download whose signature does not verify with
	// any of Config.SigningKeys, or that has none while keys are set.
	ErrBadSignature = errors.New("mghclient: the release's signature does not verify with the app's signing key; it was discarded")
	// ErrSHAMismatch is a download whose bytes do not hash to the offer.
	ErrSHAMismatch = relayclient.ErrSHAMismatch
	// ErrWrongApp is a state folder enrolled as another app.
	ErrWrongApp = errors.New("mghclient: the state folder is enrolled as another app")
)

// Config is how an application uses the relay. App and StateDir are
// required.
type Config struct {
	// App is the app's slug on the relay (the console's Apps page).
	App string
	// StateDir is where the key, certificate and state live. It is made
	// private (0700, the key 0600; an owner-only ACL on Windows). Use a
	// folder of its own, e.g. <config dir>/<app>/relay.
	StateDir string
	// Version is the version running, e.g. "v2026.11.01": the relay offers
	// nothing when it is the newest, and the console shows it.
	Version string
	// Platform is goos-arch; empty is the running one.
	Platform string
	// SigningKeys are the app's release public keys, compiled in. When set,
	// every download must carry a signature that verifies with one of them
	// (ErrBadSignature otherwise). Leave empty for an unsigned app: the
	// digest check and mutual TLS still hold.
	SigningKeys []ed25519.PublicKey

	// RelayURL overrides the relay address enrolment recorded; PublicURL
	// the public one; Route is auto (""), internal or external.
	RelayURL, PublicURL, Route string
}

func (c Config) check() error {
	if strings.TrimSpace(c.App) == "" || strings.TrimSpace(c.StateDir) == "" {
		return errors.New("mghclient: Config needs App and StateDir")
	}
	return nil
}

func (c Config) platform() string {
	if c.Platform != "" {
		return c.Platform
	}
	return runtime.GOOS + "-" + runtime.GOARCH
}

func (c Config) app() string { return strings.ToLower(strings.TrimSpace(c.App)) }

// EnrolOptions is one enrolment.
type EnrolOptions struct {
	// URL is the relay's web address, https://host[:port].
	URL string
	// Code is a one-time code from the console (Apps → app → Enrol). Empty
	// asks for approval instead, when the app allows it.
	Code string
	// AcceptFingerprint is the SHA-256 of the relay's web certificate as
	// the console shows it, needed when that certificate is self-signed.
	// Confirm, when set, is asked instead (show it, let the user say yes).
	AcceptFingerprint string
	Confirm           func(fingerprint string) (bool, error)
	// Hostname is how this machine is named in the console (default: the
	// OS's).
	Hostname string
	// Force enrols over an existing enrolment or request.
	Force bool
	// NoWait returns ErrPending as soon as the request is made (or, when
	// one is waiting, after one poll), for an app that would rather poll
	// on its own schedule. Without it Enrol blocks until a decision or ctx.
	NoWait bool
	// OnPending is told when the request is waiting for approval.
	OnPending func(Pending)
	// OnPoll is told after each poll that found it still waiting (err nil)
	// or could not reach the relay (err set; polling goes on).
	OnPoll func(Pending, error)
}

// Status is where a state folder stands.
type Status int

const (
	NotEnrolled Status = iota
	Waiting            // an enrolment request is waiting for approval
	Enrolled
)

// StatusOf reports whether cfg's state folder is enrolled, waiting for
// approval, or neither.
func StatusOf(cfg Config) Status {
	p := relayclient.Paths{Dir: cfg.StateDir}
	switch {
	case p.Complete():
		return Enrolled
	case fileExists(p.Pending()):
		return Waiting
	}
	return NotEnrolled
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// PendingRequest is the request waiting in cfg's state folder, nil when
// none is.
func PendingRequest(cfg Config) (*Pending, error) {
	return relayclient.LoadPending(relayclient.Paths{Dir: cfg.StateDir})
}

// Probe reads the relay's web certificate without sending anything: its
// fingerprint, to show the user before Enrol, and whether it chains to the
// system's roots (then there is nothing to confirm).
func Probe(ctx context.Context, url string) (fingerprint string, trusted bool, err error) {
	p, err := relayclient.ProbeWeb(ctx, url, nil)
	if err != nil {
		return "", false, err
	}
	return relayclient.FormatFingerprint(p.Fingerprint), p.Trusted, nil
}

// Enrol enrols this machine as an instance of cfg.App and opens it. With a
// code it is immediate; without, it asks for approval and waits (see
// EnrolOptions.NoWait); a request already waiting in the state folder is
// resumed rather than asked again.
func Enrol(ctx context.Context, cfg Config, o EnrolOptions) (*Instance, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	_, err := relayclient.Enroll(ctx, relayclient.EnrollOptions{
		URL: o.URL, Code: o.Code, App: cfg.app(),
		AcceptFingerprint: o.AcceptFingerprint, Confirm: o.Confirm,
		StateDir: cfg.StateDir, Force: o.Force, Hostname: o.Hostname, Version: cfg.Version,
		OnPending: o.OnPending, OnPoll: o.OnPoll, NoWait: o.NoWait, Product: cfg.app(),
	})
	if err != nil {
		return nil, err
	}
	return Open(cfg)
}

// Instance is an enrolled app instance. Its methods are safe for
// concurrent use.
type Instance struct {
	cfg Config
	c   *relayclient.Client

	mu    sync.Mutex
	every time.Duration
}

// Open loads the enrolment in cfg.StateDir. ErrNotEnrolled when there is
// none; ErrWrongApp when it is another app's.
func Open(cfg Config) (*Instance, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	if !(relayclient.Paths{Dir: cfg.StateDir}).Complete() {
		return nil, ErrNotEnrolled
	}
	c, err := relayclient.New(relayclient.Options{
		StateDir: cfg.StateDir, URL: cfg.RelayURL, PublicURL: cfg.PublicURL, Route: cfg.Route,
		Version: cfg.Version, Product: cfg.app(),
	})
	if err != nil {
		return nil, err
	}
	if app := c.State().App; app != "" && app != cfg.app() {
		return nil, fmt.Errorf("%w (%q, not %q)", ErrWrongApp, app, cfg.app())
	}
	return &Instance{cfg: cfg, c: c, every: time.Duration(protocol.InstanceCheckEvery) * time.Second}, nil
}

// ID is the instance's client id on the relay.
func (i *Instance) ID() string { return i.c.State().ClientID }

// RelayURL is the relay address in use.
func (i *Instance) RelayURL() string { return i.c.URL() }

// NotAfter is when the instance's certificate expires (Run and RenewIfDue
// renew it well before).
func (i *Instance) NotAfter() time.Time { return i.c.Identity().Leaf().NotAfter }

// Every is how long the relay asked the instance to wait between checks.
func (i *Instance) Every() time.Duration {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.every
}

// refused turns the relay's refusal of the certificate into ErrRevoked.
func refused(err error) error {
	if relayclient.IsRefused(err) {
		return ErrRevoked
	}
	return err
}

// Check asks for an update for the running version and platform: the
// offer, or nil when there is nothing to install.
func (i *Instance) Check(ctx context.Context) (*Offer, error) {
	o, err := i.c.AppUpdate(ctx, i.cfg.app(), i.cfg.platform(), i.version())
	return o, refused(err)
}

// Releases lists the releases this instance may see (its channel,
// promoted), newest first as the relay orders them.
func (i *Instance) Releases(ctx context.Context) ([]Release, error) {
	r, err := i.c.AppReleases(ctx, i.cfg.app())
	return r, refused(err)
}

// Download streams the offer's asset to w. The bytes are checked against
// the offer's SHA-256 as they stream and, when Config.SigningKeys is set,
// the signature is checked against that digest. On any error what was
// written to w must not be used — DownloadFile handles that for a file.
func (i *Instance) Download(ctx context.Context, offer *Offer, w io.Writer, progress func(int64)) error {
	if offer == nil || offer.AssetID == 0 {
		return errors.New("mghclient: no offer to download")
	}
	if err := i.verifySignature(offer); err != nil {
		return err // before a byte is fetched: a bad signature cannot become good
	}
	info, err := i.c.AppDownload(ctx, i.cfg.app(), offer.AssetID, offer.SHA256, w, progress)
	if err != nil {
		return refused(err)
	}
	if offer.SHA256 != "" && !strings.EqualFold(info.SHA256, offer.SHA256) {
		return ErrSHAMismatch
	}
	return nil
}

// verifySignature checks the offer's signature over (version, platform,
// SHA-256): the relay's digest is the one the bytes are then held to.
func (i *Instance) verifySignature(offer *Offer) error {
	if len(i.cfg.SigningKeys) == 0 {
		return nil
	}
	if offer.Signature == "" || offer.SHA256 == "" ||
		!releasekey.Verify(i.cfg.SigningKeys, offer.Version, offer.Platform, offer.SHA256, offer.Signature) {
		return ErrBadSignature
	}
	return nil
}

// DownloadFile downloads the offer to path: into path.part, renamed into
// place only once the digest (and signature) hold; nothing is left behind
// on an error.
func (i *Instance) DownloadFile(ctx context.Context, offer *Offer, path string, progress func(int64)) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	part := path + ".part"
	f, err := os.OpenFile(part, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	err = i.Download(ctx, offer, f, progress)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(part, path)
	}
	if err != nil {
		_ = os.Remove(part)
	}
	return err
}

// Report tells the relay what this instance runs (Version, Platform
// default from Config) and how its last update went. The reply carries the
// offer, so an instance that reports needs no Check, and when to check
// again (Every).
func (i *Instance) Report(ctx context.Context, r Report) (Reply, error) {
	if r.Version == "" {
		r.Version = i.version()
	}
	if r.Platform == "" {
		r.Platform = i.cfg.platform()
	}
	reply, err := i.c.AppReport(ctx, i.cfg.app(), r)
	if err != nil {
		return reply, refused(err)
	}
	if reply.Every > 0 {
		i.mu.Lock()
		i.every = time.Duration(reply.Every) * time.Second
		i.mu.Unlock()
	}
	return reply, nil
}

func (i *Instance) version() string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.cfg.Version
}

// SetVersion changes the version reported and checked against, for an app
// that swaps itself in place without restarting the process.
func (i *Instance) SetVersion(v string) {
	i.mu.Lock()
	i.cfg.Version = v
	i.mu.Unlock()
}

// RenewIfDue renews the instance's certificate when it is in its renewal
// window (30 days before expiry, or as the relay says). It reports whether
// it was renewed. Run calls it.
func (i *Instance) RenewIfDue(ctx context.Context) (bool, error) {
	var after time.Time
	if w, err := i.c.WhoAmI(ctx); err == nil {
		after = w.RenewAfter
	} else if err := refused(err); errors.Is(err, ErrRevoked) {
		return false, err
	}
	ok, err := i.c.RenewIfDue(ctx, false, after)
	return ok, refused(err)
}

// Leaf is the instance's certificate.
func (i *Instance) Leaf() *x509.Certificate { return i.c.Identity().Leaf() }

// ---------------------------------------------------------------- signing

// SignRelease signs one release asset for an app with a signing key:
// the base64 signature over (tag, goos-arch, the asset's SHA-256), which a
// release publishes as the asset <name>.sig. It is what the build of an app
// with a signing key runs; the relay passes the signature through and the
// SDK verifies it with Config.SigningKeys.
func SignRelease(priv ed25519.PrivateKey, tag, platform, sha256hex string) (string, error) {
	return releasekey.Sign(priv, tag, platform, sha256hex)
}

// VerifyRelease reports whether signature is a valid SignRelease signature
// by one of keys.
func VerifyRelease(keys []ed25519.PublicKey, tag, platform, sha256hex, signature string) bool {
	return releasekey.Verify(keys, tag, platform, sha256hex, signature)
}

// ParsePublicKey reads a signing public key in hex (the console's Signing
// key field).
func ParsePublicKey(hexKey string) (ed25519.PublicKey, error) {
	return releasekey.ParsePublicHex(hexKey)
}
