// Package relaytest is an in-process fake mghRelay for mghagent's tests: a
// web listener that answers enrolment (with a self-signed certificate, so
// trust on first use is exercised) and a mutual-TLS [relay] listener that
// serves the client API from in-memory data, speaking the protocol types.
//
// It is a test helper only. It does not import the relay's server packages:
// the client is tested against the contract in internal/protocol and
// docs/API.md, not against an implementation.
package relaytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mpaishon/mghclient/internal/protocol"
)

// Code is the one enrolment code the fake accepts (once).
const Code = "ABCD-EFGH-JKMN-PQRS"

// Data is what the fake relay serves. Repos are keyed by full name.
type Data struct {
	Profile  protocol.Profile
	Repos    []protocol.Repo
	Releases map[string][]protocol.Release
	// Blobs are asset bytes by asset id.
	Blobs map[int64][]byte
	// BadSHA lists assets served with an X-Content-SHA256 that is not the
	// hash of their bytes: a tampered cache.
	BadSHA map[int64]bool
	// Contents is directory listings: repo → path ("" is the root) → entries.
	Contents map[string]map[string][]protocol.ContentEntry
	// Files is file bodies: repo → path → body.
	Files map[string]map[string]string
	// Images is GHCR image tags by repo.
	Images map[string][]protocol.Image

	// Update is the update offer (nil: none), UpdateBody its bytes.
	Update     *protocol.Update
	UpdateBody []byte

	// CertLifetime is how long issued client certificates last (default 90 d).
	CertLifetime time.Duration
	// RenewAfter, when set, is what /whoami says.
	RenewAfter time.Time
	// ConnProfiles are the connection profiles the enrolment reply
	// advertises (N2).
	ConnProfiles []protocol.ConnectionProfile
	// Conn is the console's connection profile setting the enrolment reply
	// carries (N4).
	Conn *protocol.ConnSetting
}

// Server is the fake relay.
type Server struct {
	t testing.TB

	Web   *httptest.Server // enrolment, self-signed
	Relay *httptest.Server // the mutual-TLS client API

	// WebURL is the enrolment address; WebFingerprint its certificate's
	// SHA-256, as the operator would read it off the console.
	WebURL         string
	WebFingerprint string
	// CA is the relay CA, CAPEM its PEM.
	CA    *x509.Certificate
	CAPEM []byte
	caKey *ecdsa.PrivateKey

	mu   sync.Mutex
	data Data
	// codeUsed: codes are single use.
	codeUsed bool
	clients  map[string]bool // issued client ids → revoked?
	serial   int64

	// Requests records "METHOD path" for every relay request, and Deleted
	// every deletion asked for ("release:owner/repo:tag", "image:…").
	Requests []string
	Deleted  []string
	// UserAgents records the User-Agent of every relay request.
	UserAgents []string
	// Renewals counts renewals served.
	Renewals int
	// FailRenew makes /renew answer 500 (a relay that is down mid-renewal).
	FailRenew bool
}

// New starts a fake relay serving d. Both listeners close when the test ends.
func New(t testing.TB, d Data) *Server {
	t.Helper()
	s := &Server{t: t, data: d, clients: map[string]bool{}}
	if s.data.CertLifetime == 0 {
		s.data.CertLifetime = 90 * 24 * time.Hour
	}
	s.makeCA()

	s.Relay = httptest.NewUnstartedServer(http.HandlerFunc(s.serveRelay))
	pool := x509.NewCertPool()
	pool.AddCert(s.CA)
	s.Relay.TLS = &tls.Config{
		Certificates: []tls.Certificate{s.serverCert()},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
		// Revocation is checked on every handshake, as the relay does.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("no client certificate")
			}
			s.mu.Lock()
			revoked := s.clients[cs.PeerCertificates[0].Subject.CommonName]
			s.mu.Unlock()
			if revoked {
				return fmt.Errorf("revoked")
			}
			return nil
		},
		SessionTicketsDisabled: true,
	}
	s.Relay.StartTLS()
	t.Cleanup(s.Relay.Close)

	mux := http.NewServeMux()
	mux.HandleFunc("POST "+protocol.PathEnroll, s.serveEnroll)
	s.Web = httptest.NewTLSServer(mux)
	t.Cleanup(s.Web.Close)
	s.WebURL = s.Web.URL
	sum := sha256.Sum256(s.Web.Certificate().Raw)
	s.WebFingerprint = hex.EncodeToString(sum[:])
	return s
}

// RelayPort is the relay listener's port.
func (s *Server) RelayPort() string {
	u, _ := url.Parse(s.Relay.URL)
	return u.Port()
}

// SetData replaces what the fake serves.
func (s *Server) SetData(f func(*Data)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(&s.data)
}

// Revoke revokes every client the fake issued.
func (s *Server) Revoke() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.clients {
		s.clients[id] = true
	}
}

// Seen reports whether a request "METHOD path" was made.
func (s *Server) Seen(req string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Contains(s.Requests, req)
}

// DeletedList is a copy of Deleted.
func (s *Server) DeletedList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.Deleted)
}

func (s *Server) makeCA() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		s.t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "relaytest CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		s.t.Fatal(err)
	}
	s.CA, _ = x509.ParseCertificate(der)
	s.caKey = key
	s.CAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	s.serial = 1
}

func (s *Server) nextSerial() *big.Int {
	s.serial++
	return big.NewInt(s.serial)
}

// serverCert is the relay listener's certificate, from the relay CA, for
// 127.0.0.1 and localhost.
func (s *Server) serverCert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		s.t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: s.nextSerial(),
		Subject:      pkix.Name{CommonName: "relay"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.CA, &key.PublicKey, s.caKey)
	if err != nil {
		s.t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// issue signs a client certificate for csrPEM. The subject is the server's
// choice: whatever the CSR asks for is ignored.
func (s *Server) issue(csrPEM, clientID string) (string, time.Time, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return "", time.Time{}, fmt.Errorf("no CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", time.Time{}, err
	}
	if err := csr.CheckSignature(); err != nil {
		return "", time.Time{}, err
	}
	notAfter := time.Now().Add(s.data.CertLifetime).Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: s.nextSerial(),
		Subject:      pkix.Name{CommonName: clientID},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.CA, csr.PublicKey, s.caKey)
	if err != nil {
		return "", time.Time{}, err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), notAfter, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, protocol.Error{Error: msg})
}

func (s *Server) serveEnroll(w http.ResponseWriter, r *http.Request) {
	var req protocol.EnrollRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.Code != Code || s.codeUsed {
		fail(w, http.StatusUnauthorized, "enrolment code not accepted")
		return
	}
	clientID := fmt.Sprintf("c-%d", len(s.clients)+1)
	certPEM, notAfter, err := s.issue(req.CSRPEM, clientID)
	if err != nil {
		fail(w, http.StatusUnauthorized, "enrolment code not accepted")
		return
	}
	s.codeUsed = true
	s.clients[clientID] = false
	sum := sha256.Sum256(s.CA.Raw)
	writeJSON(w, http.StatusCreated, protocol.EnrollResponse{
		ClientID: clientID, Profile: s.data.Profile.Name, CertPEM: certPEM,
		CAPEM: string(s.CAPEM), CAFingerprint: hex.EncodeToString(sum[:]), NotAfter: notAfter,
		Relay: protocol.RelayEndpoint{Port: s.RelayPort(), Names: []string{"localhost", "127.0.0.1"}, Profiles: s.data.ConnProfiles},
		Conn:  s.data.Conn,
	})
}

func (s *Server) serveRelay(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.Requests = append(s.Requests, r.Method+" "+r.URL.Path)
	s.UserAgents = append(s.UserAgents, r.UserAgent())
	var clientID string
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		clientID = r.TLS.PeerCertificates[0].Subject.CommonName
	}
	revoked, known := s.clients[clientID]
	d := s.data
	s.mu.Unlock()
	// Revocation is re-checked per request, as the relay does.
	if !known || revoked {
		fail(w, http.StatusForbidden, "client not enrolled")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, protocol.RelayPrefix)
	switch {
	case path == "/whoami" && r.Method == http.MethodGet:
		leaf := r.TLS.PeerCertificates[0]
		renewAfter := d.RenewAfter
		if renewAfter.IsZero() {
			renewAfter = leaf.NotAfter.Add(-30 * 24 * time.Hour)
		}
		writeJSON(w, http.StatusOK, protocol.WhoAmI{
			ClientID: clientID, Label: "test machine", Profile: d.Profile,
			NotAfter: leaf.NotAfter, RenewAfter: renewAfter, Server: "v2026.10.27", Update: d.Update,
		})
	case path == "/renew" && r.Method == http.MethodPost:
		s.serveRenew(w, r, clientID)
	case path == "/repos" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"repos": d.Repos})
	case strings.HasPrefix(path, "/assets/"):
		s.serveAsset(w, r, d, strings.TrimPrefix(path, "/assets/"))
	case path == "/update" && r.Method == http.MethodGet:
		if d.Update == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, d.Update)
	case path == "/update/binary" && r.Method == http.MethodGet:
		if d.Update == nil {
			fail(w, http.StatusNotFound, "not found")
			return
		}
		sum := sha256.Sum256(d.UpdateBody)
		w.Header().Set(protocol.HeaderContentSHA256, hex.EncodeToString(sum[:]))
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(d.UpdateBody)
	case strings.HasPrefix(path, "/repos/"):
		s.serveRepo(w, r, d, strings.TrimPrefix(path, "/repos/"))
	default:
		fail(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) serveRenew(w http.ResponseWriter, r *http.Request, clientID string) {
	var req protocol.RenewRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.FailRenew {
		fail(w, http.StatusInternalServerError, "renewal failed")
		return
	}
	certPEM, notAfter, err := s.issue(req.CSRPEM, clientID)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad CSR")
		return
	}
	s.Renewals++
	writeJSON(w, http.StatusOK, protocol.RenewResponse{CertPEM: certPEM, NotAfter: notAfter})
}

// allowed is the fake's profile check: a repo the profile does not list is
// answered 404, exactly like a missing one.
func allowed(p protocol.Profile, full string) bool {
	owner, _, _ := strings.Cut(full, "/")
	for _, pat := range p.Repos {
		if pat == "*" || strings.EqualFold(pat, full) || strings.EqualFold(pat, owner+"/*") {
			return true
		}
	}
	return false
}

func (s *Server) serveAsset(w http.ResponseWriter, r *http.Request, d Data, idText string) {
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil {
		fail(w, http.StatusNotFound, "not found")
		return
	}
	var owner string
	for full, rels := range d.Releases {
		for _, rel := range rels {
			for _, a := range rel.Assets {
				if a.ID == id && allowed(d.Profile, full) {
					owner = full
				}
			}
		}
	}
	body, ok := d.Blobs[id]
	if owner == "" || !ok {
		fail(w, http.StatusNotFound, "not found")
		return
	}
	sum := sha256.Sum256(body)
	shaHex := hex.EncodeToString(sum[:])
	if d.BadSHA[id] {
		shaHex = strings.Repeat("0", 64)
	}
	w.Header().Set(protocol.HeaderContentSHA256, shaHex)
	w.Header().Set(protocol.HeaderCache, "miss")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

func (s *Server) serveRepo(w http.ResponseWriter, r *http.Request, d Data, rest string) {
	parts := strings.SplitN(rest, "/", 4)
	if len(parts) < 3 {
		fail(w, http.StatusNotFound, "not found")
		return
	}
	full := parts[0] + "/" + parts[1]
	if !allowed(d.Profile, full) {
		fail(w, http.StatusNotFound, "not found")
		return
	}
	kind, arg := parts[2], ""
	if len(parts) == 4 {
		arg = parts[3]
	}
	q := r.URL.Query()
	switch {
	case kind == "releases" && arg == "" && r.Method == http.MethodGet:
		var out []protocol.Release
		for _, rel := range d.Releases[full] {
			if slices.Contains(d.Profile.Channels, rel.Channel) {
				out = append(out, rel)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"releases": out})
	case kind == "releases" && arg != "" && r.Method == http.MethodDelete:
		if !d.Profile.Manage {
			fail(w, http.StatusNotFound, "not found")
			return
		}
		s.mu.Lock()
		s.Deleted = append(s.Deleted, "release:"+full+":"+arg)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, protocol.PurgeResult{Steps: []protocol.StepResult{
			{Step: "release", Target: full + "@" + arg, Outcome: "done"},
			{Step: "tag", Target: arg, Outcome: "done"},
			{Step: "image", Target: "ghcr.io/" + strings.ToLower(full) + ":" + arg, Outcome: "nothing_to_do"},
		}})
	case kind == "images" && arg == "" && r.Method == http.MethodGet:
		if !d.Profile.Images {
			fail(w, http.StatusNotFound, "not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"images": d.Images[full]})
	case kind == "images" && arg != "" && r.Method == http.MethodDelete:
		if !d.Profile.Manage {
			fail(w, http.StatusNotFound, "not found")
			return
		}
		s.mu.Lock()
		s.Deleted = append(s.Deleted, "image:"+full+":"+arg)
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, protocol.PurgeResult{Steps: []protocol.StepResult{
			{Step: "image", Target: arg, Outcome: "done"},
		}})
	case kind == "contents" && r.Method == http.MethodGet:
		if !d.Profile.Content {
			fail(w, http.StatusNotFound, "not found")
			return
		}
		path := q.Get("path")
		entries, ok := d.Contents[full][path]
		if !ok {
			// A file path answers with its own entry, as GitHub does.
			if body, isFile := d.Files[full][path]; isFile {
				name := path[strings.LastIndex(path, "/")+1:]
				entries = []protocol.ContentEntry{{Path: path, Name: name, Type: "file", Size: int64(len(body))}}
			} else {
				fail(w, http.StatusNotFound, "not found")
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
	case kind == "file" && r.Method == http.MethodGet:
		if !d.Profile.Content {
			fail(w, http.StatusNotFound, "not found")
			return
		}
		body, ok := d.Files[full][q.Get("path")]
		if !ok {
			fail(w, http.StatusNotFound, "not found")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, body)
	case kind == "tree" && r.Method == http.MethodGet:
		if !d.Profile.Content {
			fail(w, http.StatusNotFound, "not found")
			return
		}
		var entries []protocol.ContentEntry
		for path, body := range d.Files[full] {
			name := path[strings.LastIndex(path, "/")+1:]
			entries = append(entries, protocol.ContentEntry{Path: path, Name: name, Type: "file", Size: int64(len(body))})
		}
		for _, dir := range d.Contents[full] {
			for _, e := range dir {
				if e.Type == "dir" || e.Type == "symlink" || e.Type == "submodule" {
					entries = append(entries, e)
				}
			}
		}
		slices.SortFunc(entries, func(a, b protocol.ContentEntry) int { return strings.Compare(a.Path, b.Path) })
		entries = slices.CompactFunc(entries, func(a, b protocol.ContentEntry) bool { return a.Path == b.Path })
		writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
	default:
		fail(w, http.StatusNotFound, "not found")
	}
}

// OwnerProfile is a profile with every right, for tests that exercise the
// whole client.
func OwnerProfile() protocol.Profile {
	return protocol.Profile{
		Name: protocol.ProfileOwner, Builtin: true, Repos: []string{"*"},
		Channels: []protocol.Channel{protocol.ChannelPublished, protocol.ChannelPrerelease, protocol.ChannelDraft},
		Content:  true, Images: true, Manage: true, Links: true,
	}
}

// SHA is the hex SHA-256 of b.
func SHA(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
