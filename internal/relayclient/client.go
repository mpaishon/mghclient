package relayclient

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mpaishon/mghclient/internal/protocol"
)

// Options configure a Client.
type Options struct {
	// StateDir is the enrolment ([relay] state_dir).
	StateDir string
	// URL overrides the relay address enrolment recorded ([relay] url).
	URL string
	// r2-C: PublicURL overrides the public address the relay advertised
	// ([relay] public_url); Route is [relay] route: auto (""), internal or
	// external (D28).
	PublicURL string
	Route     string
	// Version is this build, for the User-Agent.
	Version string
	// UpdateState reports where the last self-update stands, for the
	// User-Agent; nil reports none.
	UpdateState func() string
	// Product names the client in the User-Agent; empty is mghagent. An
	// app instance gives its own name, so the relay never records its
	// version as an agent's.
	Product string
}

// Client is the mutual-TLS client of the relay's [relay] listener. It trusts
// the relay CA from enrolment and nothing else: never the system roots.
type Client struct {
	routes *router // r2-C: the addresses and the one in use
	httpc  *http.Client
	id     *Identity
	paths  Paths
	opts   Options
	stateM sync.Mutex
	state  *State
	// trying is the connection profile tried for this run only (N5).
	trying string

	lastMu    sync.Mutex
	lastCache string
}

// New loads the enrolment in o.StateDir and builds the client.
func New(o Options) (*Client, error) {
	paths := Paths{Dir: o.StateDir}
	st, err := LoadState(paths)
	if err != nil {
		return nil, err
	}
	// Every load makes the folder and the key private again (SR-12): a
	// state_dir moved, restored or created outside the profile is fixed
	// before the key is read, and one that cannot be is refused.
	if err := hardenState(paths); err != nil {
		return nil, fmt.Errorf("the relay state folder %s: %w", paths.Dir, err)
	}
	id, err := LoadIdentity(paths)
	if err != nil {
		return nil, err
	}
	raw := st.RelayURL
	if o.URL != "" {
		raw = o.URL
	}
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("relay address %q is not https://host:port", raw)
	}
	// r2-C: the route (D28). ServerName is left empty so each connection
	// checks the relay certificate against the host of the address in use.
	switch o.Route {
	case "", protocol.RouteAuto, protocol.RouteInternal, protocol.RouteExternal:
	default:
		return nil, fmt.Errorf("[relay] route %q: must be auto, internal or external", o.Route)
	}
	tlsCfg := &tls.Config{
		RootCAs:              id.Pool(),
		GetClientCertificate: id.certificate,
		MinVersion:           tls.VersionTLS12,
	}
	routes := &router{mode: RouteMode(o.Route), list: candidates(o, st), probe: handshake(tlsCfg)}
	if len(routes.list) == 0 {
		return nil, fmt.Errorf("relay address %q is not https://host:port", raw)
	}
	tr := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute, // a cache miss streams from GitHub first
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConnsPerHost:   8,
	}
	return &Client{routes: routes, httpc: &http.Client{Transport: tr}, id: id, paths: paths, opts: o, state: st}, nil
}

// base is the address in use; host its host:port.
func (c *Client) base() *url.URL { return c.routes.current().u }
func (c *Client) host() string   { return c.base().Host }

// State is the enrolment record as last saved.
func (c *Client) State() State {
	c.stateM.Lock()
	defer c.stateM.Unlock()
	return *c.state
}

// URL is the relay address in use.
func (c *Client) URL() string { return c.base().String() }

// Identity is the client's key, certificate and CA.
func (c *Client) Identity() *Identity { return c.id }

// Paths names the state folder's files.
func (c *Client) Paths() Paths { return c.paths }

// LastCache is X-Relay-Cache of the last download: hit, miss or "".
func (c *Client) LastCache() string {
	c.lastMu.Lock()
	defer c.lastMu.Unlock()
	return c.lastCache
}

// StatusError is a relay reply that was not 2xx.
type StatusError struct {
	Code    int
	Message string
	// WAN is the relay's X-Relay-WAN-Refused: the request came from outside
	// and WAN access is off for this client ("client") or for everyone
	// ("household"). r2-C.
	WAN string
}

func (e *StatusError) Error() string {
	if e.WAN != "" {
		if e.WAN == protocol.WANOffHousehold {
			return "the relay refused this request from outside its local network: it does not allow clients from outside (" + protocol.WANRefusedMessage + ")"
		}
		return "the relay refused this request from outside its local network: " + protocol.WANRefusedMessage +
			"; an admin turns on Allow WAN in the client's drawer, or use the relay from the local network (mghagent --relay-route internal)"
	}
	switch e.Code {
	case http.StatusNotFound:
		// The relay answers the same 404 for "missing" and "not in your
		// profile", on purpose; say both.
		return "not found on the relay (or not in this client's access profile)"
	case http.StatusForbidden, http.StatusUnauthorized:
		return "the relay refused this client: it may have been revoked; enrol again with a new code"
	}
	if e.Message != "" {
		return fmt.Sprintf("relay: HTTP %d: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("relay: HTTP %d", e.Code)
}

// StatusOf is the HTTP status in a relay error, or 0.
func StatusOf(err error) int {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code
	}
	return 0
}

// ErrSHAMismatch is a download whose bytes are not the ones the relay vouched
// for. Nothing of it may be used.
var ErrSHAMismatch = errors.New("the download's SHA-256 does not match X-Content-SHA256; it was discarded")

func (c *Client) endpoint(path string, q url.Values) string {
	b := c.base()
	u := *b
	u.Path = strings.TrimRight(b.Path, "/") + path
	u.RawPath = ""
	if len(q) > 0 {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

func (c *Client) do(ctx context.Context, method, path string, q url.Values, body io.Reader) (*http.Response, error) {
	c.routes.ready(ctx) // r2-C: choose (or re-check) the address first
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(path, q), body)
	if err != nil {
		return nil, err
	}
	update := ""
	if c.opts.UpdateState != nil {
		update = c.opts.UpdateState()
	}
	req.Header.Set("User-Agent", userAgentFor(c.opts.Product, c.opts.Version, update))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			c.routes.failed() // r2-C: the next request picks an address again
		}
		return nil, fmt.Errorf("relay %s: %w", req.URL.Host, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		return nil, &StatusError{Code: resp.StatusCode, Message: errorText(raw), WAN: resp.Header.Get(protocol.HeaderWANRefused)}
	}
	return resp, nil
}

func (c *Client) getJSON(ctx context.Context, path string, q url.Values, out any) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	resp, err := c.do(ctx, http.MethodGet, path, q, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}
	if err := decode(resp.Body, out); err != nil {
		return resp.StatusCode, fmt.Errorf("relay %s%s: %w", c.host(), path, err)
	}
	return resp.StatusCode, nil
}

func decode(r io.Reader, out any) error {
	raw, err := io.ReadAll(io.LimitReader(r, maxReply+1))
	if err != nil {
		return err
	}
	if len(raw) > maxReply {
		return errors.New("reply too large")
	}
	return json.Unmarshal(raw, out)
}

// repoPath is /relay/repos/<owner>/<repo><suffix>, escaped.
func repoPath(owner, repo, suffix string) string {
	return protocol.PathRepos + "/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + suffix
}

// WhoAmI asks who this client is to the relay: its profile, its certificate's
// renewal time and the update on offer.
func (c *Client) WhoAmI(ctx context.Context) (protocol.WhoAmI, error) {
	var w protocol.WhoAmI
	_, err := c.getJSON(ctx, protocol.PathWhoAmI, nil, &w)
	return w, err
}

// Repos lists the repositories this client's profile may see.
func (c *Client) Repos(ctx context.Context) ([]protocol.Repo, error) {
	var r struct {
		Repos []protocol.Repo `json:"repos"`
	}
	_, err := c.getJSON(ctx, protocol.PathRepos, nil, &r)
	return r.Repos, err
}

// Releases lists a repository's releases, assets included, filtered by the
// profile's channels.
func (c *Client) Releases(ctx context.Context, owner, repo string) ([]protocol.Release, error) {
	var r struct {
		Releases []protocol.Release `json:"releases"`
	}
	_, err := c.getJSON(ctx, repoPath(owner, repo, "/releases"), nil, &r)
	return r.Releases, err
}

// Contents lists a directory of a repository (profile content).
func (c *Client) Contents(ctx context.Context, owner, repo, path, ref string) ([]protocol.ContentEntry, error) {
	var r struct {
		Entries []protocol.ContentEntry `json:"entries"`
	}
	q := url.Values{}
	q.Set("path", path)
	if ref != "" {
		q.Set("ref", ref)
	}
	_, err := c.getJSON(ctx, repoPath(owner, repo, "/contents"), q, &r)
	return r.Entries, err
}

// Tree lists every entry of a repository at ref (profile content).
func (c *Client) Tree(ctx context.Context, owner, repo, ref string) ([]protocol.ContentEntry, error) {
	var r struct {
		Entries []protocol.ContentEntry `json:"entries"`
	}
	q := url.Values{}
	if ref != "" {
		q.Set("ref", ref)
	}
	_, err := c.getJSON(ctx, repoPath(owner, repo, "/tree"), q, &r)
	return r.Entries, err
}

// Images lists a repository's container images on GHCR (profile images).
func (c *Client) Images(ctx context.Context, owner, repo string) ([]protocol.Image, error) {
	var r struct {
		Images []protocol.Image `json:"images"`
	}
	_, err := c.getJSON(ctx, repoPath(owner, repo, "/images"), nil, &r)
	return r.Images, err
}

func (c *Client) deleteJSON(ctx context.Context, path string) (protocol.PurgeResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var res protocol.PurgeResult
	resp, err := c.do(ctx, http.MethodDelete, path, nil, nil)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()
	if err := decode(resp.Body, &res); err != nil {
		return res, fmt.Errorf("relay %s%s: %w", c.host(), path, err)
	}
	return res, nil
}

// DeleteRelease deletes a release on GitHub through the relay (profile
// manage): release, tag, then image, as bld release --delete does.
func (c *Client) DeleteRelease(ctx context.Context, owner, repo, tag string) (protocol.PurgeResult, error) {
	return c.deleteJSON(ctx, repoPath(owner, repo, "/releases/"+url.PathEscape(tag)))
}

// DeleteImage deletes one image tag on GHCR through the relay (profile
// manage).
func (c *Client) DeleteImage(ctx context.Context, owner, repo, tag string) (protocol.PurgeResult, error) {
	return c.deleteJSON(ctx, repoPath(owner, repo, "/images/"+url.PathEscape(tag)))
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// DownloadInfo describes a finished, verified download.
type DownloadInfo struct {
	SHA256 string
	Bytes  int64
	Cache  string // X-Relay-Cache: hit or miss
}

// DownloadAsset streams a release asset to dst, hashing as it writes, and
// fails with ErrSHAMismatch unless the bytes are exactly the ones
// X-Content-SHA256 names. expectSHA, when known from the catalog, must match
// that header too, so a relay cannot vouch for different bytes than it
// listed. The caller must not use what it wrote on any error: download.Run
// writes into a .part file it removes, and extracts only after this returns
// nil.
func (c *Client) DownloadAsset(ctx context.Context, id int64, expectSHA string, dst io.Writer, progress func(int64)) (DownloadInfo, error) {
	resp, err := c.do(ctx, http.MethodGet, protocol.PathAssets+strconv.FormatInt(id, 10), nil, nil)
	if err != nil {
		return DownloadInfo{}, err
	}
	defer resp.Body.Close()
	info := DownloadInfo{Cache: resp.Header.Get(protocol.HeaderCache)}
	c.lastMu.Lock()
	c.lastCache = info.Cache
	c.lastMu.Unlock()
	return info, verifiedCopy(resp, expectSHA, dst, progress, &info)
}

// verifiedCopy copies a download body to dst while hashing it, and checks the
// whole against X-Content-SHA256.
func verifiedCopy(resp *http.Response, expectSHA string, dst io.Writer, progress func(int64), info *DownloadInfo) error {
	want := strings.ToLower(strings.TrimSpace(resp.Header.Get(protocol.HeaderContentSHA256)))
	if !sha256Hex.MatchString(want) {
		return fmt.Errorf("the relay sent no valid %s header; the download was refused", protocol.HeaderContentSHA256)
	}
	if e := strings.ToLower(strings.TrimSpace(expectSHA)); e != "" && e != want {
		return fmt.Errorf("the relay listed this asset with SHA-256 %s but serves %s; the download was refused", e, want)
	}
	h := sha256.New()
	n, err := copyProgress(io.MultiWriter(dst, h), resp.Body, progress)
	info.Bytes = n
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if resp.ContentLength >= 0 && n != resp.ContentLength {
		return fmt.Errorf("download: got %d bytes of %d", n, resp.ContentLength)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return ErrSHAMismatch
	}
	info.SHA256 = got
	return nil
}

// copyProgress copies src to dst, reporting the cumulative bytes written.
func copyProgress(dst io.Writer, src io.Reader, progress func(int64)) (int64, error) {
	buf := make([]byte, 64<<10)
	var written int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, err := dst.Write(buf[:n]); err != nil {
				return written, err
			}
			written += int64(n)
			if progress != nil {
				progress(written)
			}
		}
		if rerr == io.EOF {
			return written, nil
		}
		if rerr != nil {
			return written, rerr
		}
	}
}

// File streams one repository file to dst (profile content). When the relay
// vouches for the bytes with X-Content-SHA256 they are checked too.
func (c *Client) File(ctx context.Context, owner, repo, path, ref string, dst io.Writer, progress func(int64)) error {
	q := url.Values{}
	q.Set("path", path)
	if ref != "" {
		q.Set("ref", ref)
	}
	resp, err := c.do(ctx, http.MethodGet, repoPath(owner, repo, "/file"), q, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.Header.Get(protocol.HeaderContentSHA256) != "" {
		return verifiedCopy(resp, "", dst, progress, &DownloadInfo{})
	}
	_, err = copyProgress(dst, resp.Body, progress)
	return err
}

// Update is the relay's update offer for platform, nil when it has none.
func (c *Client) Update(ctx context.Context, platform string) (*protocol.Update, error) {
	var u protocol.Update
	q := url.Values{}
	q.Set("platform", platform)
	code, err := c.getJSON(ctx, protocol.PathUpdate, q, &u)
	if err != nil {
		return nil, err
	}
	if code == http.StatusNoContent || u.Version == "" {
		return nil, nil
	}
	return &u, nil
}

// UpdateBinary opens the offered release zip for platform; the caller hashes
// it as it writes (internal/clientupdate checks it against the signed
// SHA-256) and closes it. X-Content-SHA256 must be present and, when
// expectSHA (the signed offer's) is given, equal to it, so a relay that
// serves other bytes than it offered is refused before a byte is read.
func (c *Client) UpdateBinary(ctx context.Context, platform, expectSHA string) (io.ReadCloser, error) {
	q := url.Values{}
	q.Set("platform", platform)
	resp, err := c.do(ctx, http.MethodGet, protocol.PathUpdateBinary, q, nil)
	if err != nil {
		return nil, err
	}
	got := strings.ToLower(strings.TrimSpace(resp.Header.Get(protocol.HeaderContentSHA256)))
	if !sha256Hex.MatchString(got) {
		resp.Body.Close()
		return nil, fmt.Errorf("the relay sent no valid %s header with the update; refused", protocol.HeaderContentSHA256)
	}
	if e := strings.ToLower(expectSHA); e != "" && e != got {
		resp.Body.Close()
		return nil, fmt.Errorf("the relay serves an update zip with SHA-256 %s, not the offered %s; refused", got, e)
	}
	return resp.Body, nil
}

// ErrRefused is the relay refusing this client's certificate, at the
// handshake or on a request: the client was revoked, or is not (or no
// longer) enrolled there.
var ErrRefused = errors.New("the relay refused this client's certificate: it has been revoked or is not enrolled; enrol again with a new code")

// Ping makes one authenticated request (GET /relay/whoami) on a fresh
// connection, for --doctor. It proves the relay's certificate chains to the
// enrolment CA for this host name and that the relay accepts this client.
// A bare handshake proves less than it seems (SR-10, R7): under TLS 1.3 the
// client finishes its side before the relay judges the certificate, so a
// revoked client's handshake "succeeds" and the refusal arrives with the
// first read. A refusal is ErrRefused.
func (c *Client) Ping(ctx context.Context) (time.Duration, error) {
	tr := c.httpc.Transport.(*http.Transport).Clone()
	tr.DisableKeepAlives = true // a new handshake, judged against today's revocations
	defer tr.CloseIdleConnections()
	c.routes.ready(ctx) // r2-C
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(protocol.PathWhoAmI, nil), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", userAgentFor(c.opts.Product, c.opts.Version, ""))
	start := time.Now()
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		if certificateRefused(err) {
			return 0, ErrRefused
		}
		return 0, fmt.Errorf("relay %s: %w", c.host(), err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxReply))
	resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusForbidden && resp.Header.Get(protocol.HeaderWANRefused) != "": // r2-C
		return 0, &StatusError{Code: resp.StatusCode, WAN: resp.Header.Get(protocol.HeaderWANRefused)}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return 0, ErrRefused
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return 0, &StatusError{Code: resp.StatusCode}
	}
	return time.Since(start), nil
}

// certificateRefused reports a TLS alert from the relay about this client's
// certificate (bad certificate, certificate revoked, unknown, required…).
func certificateRefused(err error) bool {
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "remote error" && op.Err != nil {
		return strings.Contains(op.Err.Error(), "certificate")
	}
	msg := err.Error()
	return strings.Contains(msg, "remote error: tls:") && strings.Contains(msg, "certificate")
}
