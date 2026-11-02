package relayclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/mpaishon/mghclient/internal/protocol"
)

// The files the client keeps in its state folder ([relay] state_dir). Ported
// from File Cellar's internal/syncclient/state.go, which keeps the same set
// for its sync client.
const (
	KeyFile    = "client.key"  // the private key, 0600; it never leaves the machine
	CertFile   = "client.crt"  // the client certificate the relay issued
	CAFile     = "ca.crt"      // the relay's CA: the only trust for every relay connection
	StateFile  = "state.json"  // identity and where the relay is; written last at enrolment
	UpdateFile = "update.json" // where the last self-update stands (internal/clientupdate)

	// nextSuffix marks a renewed key and certificate written in full before
	// they replace the current pair; prevSuffix keeps the pair a renewal
	// replaced, one generation.
	nextSuffix = ".next"
	prevSuffix = ".prev"
)

// Paths names the files in a state folder.
type Paths struct{ Dir string }

func (p Paths) Key() string    { return filepath.Join(p.Dir, KeyFile) }
func (p Paths) Cert() string   { return filepath.Join(p.Dir, CertFile) }
func (p Paths) CA() string     { return filepath.Join(p.Dir, CAFile) }
func (p Paths) State() string  { return filepath.Join(p.Dir, StateFile) }
func (p Paths) Update() string { return filepath.Join(p.Dir, UpdateFile) }

// Enrolled reports whether the folder holds an enrolment, or the beginning
// of one: a state file, a certificate or a key.
func (p Paths) Enrolled() bool {
	for _, f := range []string{p.State(), p.Cert(), p.Key()} {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	return false
}

// Complete reports whether the folder holds a finished enrolment. The state
// file is written last, so it is the mark.
func (p Paths) Complete() bool {
	_, err := os.Stat(p.State())
	return err == nil
}

// State is state.json: who this client is to the relay and where the relay
// is. It is the client's own record, never configuration (client.toml is).
type State struct {
	Version  int    `json:"version"`
	ClientID string `json:"client_id"`
	// Profile is the access profile the enrolment code was made for; the
	// relay may change it later, and /whoami says what it is now.
	Profile string `json:"profile"`
	// Hostname is what this machine called itself at enrolment.
	Hostname string `json:"hostname,omitempty"`
	// RelayURL is the mutual-TLS client API, https://host:port.
	RelayURL string `json:"relay_url"`
	// WebURL is where the client enrolled (the relay's web listener).
	WebURL        string `json:"web_url"`
	CAFingerprint string `json:"ca_fingerprint"`
	// WebFingerprint is the web certificate the operator accepted on first
	// use; empty when it chained to the system roots.
	WebFingerprint string     `json:"web_fingerprint,omitempty"`
	RelayNames     []string   `json:"relay_names,omitempty"`
	EnrolledAt     time.Time  `json:"enrolled_at"`
	NotAfter       time.Time  `json:"not_after"`
	RenewedAt      *time.Time `json:"renewed_at,omitempty"`
	// r2-C: the relay's internal and public addresses as it last advertised
	// them (https://host:port), at enrolment and at every check-in (D28).
	// [relay] url and public_url in client.toml override them.
	InternalURL string `json:"internal_url,omitempty"`
	PublicURL   string `json:"public_url,omitempty"`
	// N2: the relay's connection profiles as it last advertised them, and
	// this machine's choice: the primary profile ("" = automatic, by the
	// relay's order), whether to stay on it when it cannot be reached, and
	// who locked the choice ("console", or "" — N3). Kept here, not in
	// client.toml, so a client rolled back one release still starts: it
	// ignores fields it does not know.
	Profiles       []protocol.ConnectionProfile `json:"profiles,omitempty"`
	ConnProfile    string                       `json:"conn_profile,omitempty"`
	ConnNoFallback bool                         `json:"conn_no_fallback,omitempty"`
	ConnLockedBy   string                       `json:"conn_locked_by,omitempty"`
	// ConnRev is the console setting last applied (N3).
	ConnRev int64 `json:"conn_rev,omitempty"`
	// App is the app this client enrolled as an instance of
	// (docs/UPGRADE_GATEWAY.md); "" for the relay's own client.
	App string `json:"app,omitempty"`
}

const stateVersion = 1

// ErrNotEnrolled is a state folder with no enrolment in it.
var ErrNotEnrolled = errors.New("this machine is not enrolled with a relay: run mghagent --enroll <url> --code <code>, or mghagent --setup")

// LoadState reads state.json.
func LoadState(p Paths) (*State, error) {
	raw, err := os.ReadFile(p.State())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, fmt.Errorf("read the relay state: %w", err)
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("%s is damaged (%v): enrol again with --enroll --force", p.State(), err)
	}
	if st.Version > stateVersion {
		return nil, fmt.Errorf("%s was written by a newer mghagent (state version %d)", p.State(), st.Version)
	}
	if st.ClientID == "" || st.RelayURL == "" {
		return nil, fmt.Errorf("%s has no client id or relay address: enrol again with --enroll --force", p.State())
	}
	return &st, nil
}

// SaveState writes state.json atomically, 0600.
func SaveState(p Paths, st *State) error {
	st.Version = stateVersion
	raw, err := json.MarshalIndent(st, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return err
	}
	return writeFile(p.State(), raw, 0o600)
}

// writeFile writes data to path atomically: a temporary file in the same
// folder, synced, then renamed over path. A crash leaves the old file or the
// new one, never half of either.
func writeFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.new")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Chmod(mode); err != nil && !isUnsupported(err) {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	afterWrite(path)
	return nil
}

// afterWrite hears of every file written, in order; tests use it to prove
// the key is written first and the state last.
var afterWrite = func(string) {}

// isUnsupported is a chmod the platform does not do on an open file
// (Windows); the mode is applied by path after the rename instead.
func isUnsupported(err error) bool {
	var pe *fs.PathError
	return errors.As(err, &pe)
}
