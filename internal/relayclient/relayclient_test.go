package relayclient

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mpaishon/mghclient/internal/protocol"
	"github.com/mpaishon/mghclient/internal/relayclient/relaytest"
)

func fakeData() relaytest.Data {
	payload := []byte("the build")
	return relaytest.Data{
		Profile: relaytest.OwnerProfile(),
		Repos:   []protocol.Repo{{Owner: "me", Name: "app", FullName: "me/app", DefaultBranch: "main"}},
		Releases: map[string][]protocol.Release{"me/app": {{
			ID: 1, Repo: "me/app", Tag: "v1", Channel: protocol.ChannelPublished,
			Assets: []protocol.Asset{{ID: 10, Name: "app.zip", Size: int64(len(payload)), SHA256: relaytest.SHA(payload)}, {ID: 11, Name: "bad.zip", Size: 3}},
		}}},
		Blobs:  map[int64][]byte{10: payload, 11: []byte("bad")},
		BadSHA: map[int64]bool{11: true},
	}
}

func enroll(t *testing.T, s *relaytest.Server) (string, *EnrollResult) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	res, err := Enroll(context.Background(), EnrollOptions{
		URL: s.WebURL, Code: relaytest.Code, AcceptFingerprint: s.WebFingerprint,
		StateDir: dir, Hostname: "test-host", Version: "v2026.10.27",
	})
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	return dir, res
}

func newClient(t *testing.T, dir string) *Client {
	t.Helper()
	c, err := New(Options{StateDir: dir, Version: "v2026.10.27"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The key is written first, with 0600, and the state file last: a state
// file means a complete enrolment, and the key never sits world-readable.
func TestEnrollWritesKeyFirst0600(t *testing.T) {
	s := relaytest.New(t, fakeData())
	var order []string
	afterWrite = func(p string) { order = append(order, filepath.Base(p)) }
	t.Cleanup(func() { afterWrite = func(string) {} })

	dir, res := enroll(t, s)
	if len(order) == 0 || order[0] != KeyFile || order[len(order)-1] != StateFile {
		t.Fatalf("write order = %v, want %s first and %s last", order, KeyFile, StateFile)
	}
	if runtime.GOOS != "windows" {
		for name, want := range map[string]os.FileMode{KeyFile: 0o600, StateFile: 0o600} {
			info, err := os.Stat(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != want {
				t.Errorf("%s mode = %o, want %o", name, got, want)
			}
		}
		if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
			t.Errorf("state dir mode = %o, want 700", info.Mode().Perm())
		}
	}
	st, err := LoadState(Paths{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if st.ClientID != res.ClientID || st.WebFingerprint != s.WebFingerprint || !strings.HasSuffix(st.RelayURL, ":"+s.RelayPort()) {
		t.Errorf("state = %+v", st)
	}
	key, _ := os.ReadFile(filepath.Join(dir, KeyFile))
	if !bytes.Contains(key, []byte("PRIVATE KEY")) {
		t.Error("client.key holds no private key")
	}
}

// A self-signed web certificate is trusted only on a matching fingerprint,
// a typed yes, or not at all; nothing is sent otherwise.
func TestEnrollTrustOnFirstUse(t *testing.T) {
	s := relaytest.New(t, fakeData())
	base := EnrollOptions{URL: s.WebURL, Code: relaytest.Code}

	o := base
	o.StateDir = t.TempDir()
	var fe *FingerprintError
	if _, err := Enroll(context.Background(), o); !errors.As(err, &fe) || fe.Mismatch || fe.Fingerprint != s.WebFingerprint {
		t.Fatalf("no fingerprint: err = %v", err)
	}

	o.AcceptFingerprint = strings.Repeat("ab", 32)
	if _, err := Enroll(context.Background(), o); !errors.As(err, &fe) || !fe.Mismatch {
		t.Fatalf("wrong fingerprint: err = %v", err)
	}

	o.AcceptFingerprint = ""
	var asked string
	o.Confirm = func(fp string) (bool, error) { asked = fp; return false, nil }
	if _, err := Enroll(context.Background(), o); !errors.As(err, &fe) || asked != s.WebFingerprint {
		t.Fatalf("declined: err = %v, asked %q", err, asked)
	}
	if (Paths{Dir: o.StateDir}).Enrolled() {
		t.Fatal("a refused enrolment left files behind")
	}

	// The fingerprint may be typed with colons and in upper case.
	o.Confirm = nil
	o.AcceptFingerprint = strings.ToUpper(FormatFingerprint(s.WebFingerprint))
	if _, err := Enroll(context.Background(), o); err != nil {
		t.Fatalf("accepted fingerprint: %v", err)
	}
}

func TestEnrollRefusesPlainHTTPAndPaths(t *testing.T) {
	for _, u := range []string{"http://relay:8444", "https://relay:8444/ui", "https://user@relay", "relay:8444"} {
		if _, _, err := WebAddress(u); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
	if host, addr, err := WebAddress("https://relay.example.com"); err != nil || host != "relay.example.com" || addr != "relay.example.com:443" {
		t.Errorf("default port: %s %s %v", host, addr, err)
	}
}

func TestEnrollCodeIsSingleUseAndStateIsNotOverwritten(t *testing.T) {
	s := relaytest.New(t, fakeData())
	dir, _ := enroll(t, s)
	_, err := Enroll(context.Background(), EnrollOptions{URL: s.WebURL, Code: relaytest.Code, AcceptFingerprint: s.WebFingerprint, StateDir: dir})
	if !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("second enrolment into the same folder: %v", err)
	}
	_, err = Enroll(context.Background(), EnrollOptions{URL: s.WebURL, Code: relaytest.Code, AcceptFingerprint: s.WebFingerprint, StateDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "did not accept the code") {
		t.Fatalf("reused code: %v", err)
	}
}

func TestClientSpeaksMutualTLSWithTheEnrolmentCAOnly(t *testing.T) {
	s := relaytest.New(t, fakeData())
	dir, _ := enroll(t, s)
	c := newClient(t, dir)
	who, err := c.WhoAmI(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if who.Profile.Name != protocol.ProfileOwner || who.ClientID != c.State().ClientID {
		t.Errorf("whoami = %+v", who)
	}
	repos, err := c.Repos(context.Background())
	if err != nil || len(repos) != 1 {
		t.Fatalf("repos = %v, %v", repos, err)
	}
	// The user agent names the version, the platform and the update state.
	ua := s.UserAgents[len(s.UserAgents)-1]
	if !strings.HasPrefix(ua, "mghagent/v2026.10.27 ("+runtime.GOOS+"-"+runtime.GOARCH+"; update=") {
		t.Errorf("user agent = %q", ua)
	}

	// A CA other than the enrolment's is never trusted: replacing ca.crt
	// with another CA makes the relay's certificate unverifiable.
	other := relaytest.New(t, fakeData())
	if err := os.WriteFile(filepath.Join(dir, CAFile), other.CAPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{StateDir: dir}); err == nil {
		t.Fatal("a client certificate that does not chain to ca.crt was accepted")
	}
}

func TestDownloadRejectsBadSHA(t *testing.T) {
	s := relaytest.New(t, fakeData())
	dir, _ := enroll(t, s)
	c := newClient(t, dir)

	var good bytes.Buffer
	info, err := c.DownloadAsset(context.Background(), 10, relaytest.SHA([]byte("the build")), &good, nil)
	if err != nil || good.String() != "the build" || info.SHA256 != relaytest.SHA([]byte("the build")) || info.Cache != "miss" {
		t.Fatalf("good download: %+v %q %v", info, good.String(), err)
	}

	var bad bytes.Buffer
	if _, err := c.DownloadAsset(context.Background(), 11, "", &bad, nil); !errors.Is(err, ErrSHAMismatch) {
		t.Fatalf("tampered download: err = %v", err)
	}

	// The catalog's hash must agree with the header before a byte is used.
	var wrong bytes.Buffer
	if _, err := c.DownloadAsset(context.Background(), 10, strings.Repeat("1", 64), &wrong, nil); err == nil || wrong.Len() != 0 {
		t.Fatalf("listed/served mismatch: err = %v, wrote %d bytes", err, wrong.Len())
	}

	if _, err := c.DownloadAsset(context.Background(), 99, "", &bytes.Buffer{}, nil); StatusOf(err) != 404 {
		t.Fatalf("missing asset: %v", err)
	}
}

func TestRenewalSwapsTheCertificateLive(t *testing.T) {
	s := relaytest.New(t, fakeData())
	dir, _ := enroll(t, s)
	c := newClient(t, dir)
	before := c.Identity().Leaf().SerialNumber

	if renewed, err := c.RenewIfDue(context.Background(), false, time.Time{}); err != nil || renewed {
		t.Fatalf("a fresh certificate renewed: %v %v", renewed, err)
	}
	if renewed, err := c.RenewIfDue(context.Background(), false, time.Now().Add(-time.Minute)); err != nil || !renewed {
		t.Fatalf("relay's renew_after passed but no renewal: %v %v", renewed, err)
	}
	if c.Identity().Leaf().SerialNumber.Cmp(before) == 0 {
		t.Fatal("the certificate did not change")
	}
	// The same client keeps working on the new certificate, and a fresh
	// load reads it from disk.
	if _, err := c.WhoAmI(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := newClient(t, dir).Identity().Leaf().SerialNumber; got.Cmp(c.Identity().Leaf().SerialNumber) != 0 {
		t.Error("the renewed certificate was not installed on disk")
	}
	for _, f := range []string{KeyFile + prevSuffix, CertFile + prevSuffix} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s not kept: %v", f, err)
		}
	}
	for _, f := range []string{KeyFile + nextSuffix, CertFile + nextSuffix} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			t.Errorf("%s left behind", f)
		}
	}
}

// A renewal interrupted at either point a crash could hit is finished at the
// next start, and the client works on the new certificate.
func TestInterruptedRenewalCompletes(t *testing.T) {
	for _, stop := range []renewStep{stepNextWritten, stepKeyInstalled} {
		s := relaytest.New(t, fakeData())
		dir, _ := enroll(t, s)
		c := newClient(t, dir)
		old := c.Identity().Leaf().SerialNumber

		crash := errors.New("crash")
		renewInterrupt = func(st renewStep) error {
			if st == stop {
				return crash
			}
			return nil
		}
		err := c.Renew(context.Background())
		renewInterrupt = func(renewStep) error { return nil }
		if !errors.Is(err, crash) {
			t.Fatalf("step %d: renew = %v", stop, err)
		}

		c2 := newClient(t, dir) // LoadIdentity finishes the renewal
		if c2.Identity().Leaf().SerialNumber.Cmp(old) == 0 {
			t.Fatalf("step %d: still on the old certificate", stop)
		}
		if _, err := c2.WhoAmI(context.Background()); err != nil {
			t.Fatalf("step %d: whoami on the finished renewal: %v", stop, err)
		}
		for _, f := range []string{KeyFile + nextSuffix, CertFile + nextSuffix} {
			if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
				t.Errorf("step %d: %s left behind", stop, f)
			}
		}
	}
}

// Only a key with no certificate yet is dropped, keeping the pair that works.
func TestHalfWrittenRenewalIsDropped(t *testing.T) {
	s := relaytest.New(t, fakeData())
	dir, _ := enroll(t, s)
	keyNext := filepath.Join(dir, KeyFile+nextSuffix)
	key, _, err := GenerateKeyAndCSR("x")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyNext, key, 0o600); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, dir)
	if _, err := c.WhoAmI(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keyNext); err == nil {
		t.Error("an orphan key.next was kept")
	}
}

func TestRevokedClientIsToldSo(t *testing.T) {
	s := relaytest.New(t, fakeData())
	dir, _ := enroll(t, s)
	c := newClient(t, dir)
	s.Revoke()
	_, err := c.WhoAmI(context.Background())
	if err == nil {
		t.Fatal("a revoked client was served")
	}
	if err := c.Renew(context.Background()); err == nil {
		t.Fatal("a revoked client renewed")
	}
}

func TestRenewDueFallsBackToThirtyDays(t *testing.T) {
	now := time.Now()
	leaf := &x509.Certificate{NotBefore: now.Add(-60 * 24 * time.Hour), NotAfter: now.Add(31 * 24 * time.Hour)}
	if RenewDue(leaf, now, time.Time{}) {
		t.Error("31 days left: not due yet")
	}
	leaf.NotAfter = now.Add(29 * 24 * time.Hour)
	if !RenewDue(leaf, now, time.Time{}) {
		t.Error("29 days left: due")
	}
	if RenewDue(leaf, now, now.Add(time.Hour)) {
		t.Error("the relay's renew_after wins")
	}
}

func TestUpdateOffer(t *testing.T) {
	d := fakeData()
	s := relaytest.New(t, d)
	dir, _ := enroll(t, s)
	c := newClient(t, dir)
	if u, err := c.Update(context.Background(), "linux-amd64"); err != nil || u != nil {
		t.Fatalf("no offer: %v %v", u, err)
	}
	s.SetData(func(d *relaytest.Data) {
		d.Update = &protocol.Update{Version: "v2026.11.01", Policy: protocol.UpdateNotify}
		d.UpdateBody = []byte("zip")
	})
	u, err := c.Update(context.Background(), "linux-amd64")
	if err != nil || u == nil || u.Version != "v2026.11.01" {
		t.Fatalf("offer: %v %v", u, err)
	}
	if !slices.Contains(s.Requests, "GET /relay/update") {
		t.Errorf("requests = %v", s.Requests)
	}
}
