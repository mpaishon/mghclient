package relayclient

// r2-C: which relay address a client uses (D28), after File Cellar's
// internal/syncclient/route.go. A client may know the relay on the local
// network (the address it enrolled through, [relay] url, and the internal
// address the relay advertises) and from outside (the public address the
// relay advertises, or [relay] public_url). [relay] route chooses:
//
//   - auto tries the internal addresses first, each with a full mutual-TLS
//     handshake bounded by probeTimeout, and falls back to the public one;
//     on the fallback it tries the internal one again at most once per
//     preferEvery;
//   - internal uses the internal addresses only;
//   - external — the operator's "we are external" — the public one only
//     (the internal ones when the relay has advertised none).
//
// The listener is the same mutual TLS on every address, so switching is
// only a matter of where the next connection goes. The certificate is
// checked against the host of the address in use.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/mpaishon/mghclient/internal/protocol"
)

const (
	// probeTimeout bounds one reachability check: a TCP connect and the
	// mutual-TLS handshake.
	probeTimeout = 4 * time.Second
	// pickEvery stops a burst of failed requests from probing over and over.
	pickEvery = 5 * time.Second
	// preferEvery is how often a client on its fallback address checks
	// whether the preferred one is back.
	preferEvery = 60 * time.Second
)

// candidate is one address a client may use.
type candidate struct {
	u    *url.URL
	kind string // protocol.RouteInternal or protocol.RouteExternal
	// N2: the connection profile it is (id and name); "" for an address
	// that is none of the relay's profiles ([relay] url, the enrolment
	// address kept as a last resort).
	profile, name string
}

// router holds the addresses one client tries, in order, and the one in
// use. Safe for concurrent use.
type router struct {
	mode string

	mu      sync.Mutex
	list    []candidate
	cur     int
	picked  time.Time // last full pick; zero: pick before the next request
	checked time.Time // last check of the preferred address
	// probe is a full handshake with one address (tests replace it).
	probe func(ctx context.Context, u *url.URL) bool
}

// RouteMode is a [relay] route value with the default applied.
func RouteMode(mode string) string {
	if mode == "" {
		return protocol.RouteAuto
	}
	return mode
}

// RouteURLs is the addresses a route tries, in order, from the internal
// addresses (first is preferred) and the public one. external without a
// public address falls back to the internal ones.
func RouteURLs(internal []string, public, mode string) []candidate {
	var ins []candidate
	seen := map[string]bool{}
	add := func(list *[]candidate, raw, kind string) {
		raw = strings.TrimRight(strings.TrimSpace(raw), "/")
		if raw == "" || seen[strings.ToLower(raw)] {
			return
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return
		}
		seen[strings.ToLower(raw)] = true
		*list = append(*list, candidate{u: u, kind: kind})
	}
	for _, raw := range internal {
		add(&ins, raw, protocol.RouteInternal)
	}
	var pub []candidate
	add(&pub, public, protocol.RouteExternal)
	switch RouteMode(mode) {
	case protocol.RouteInternal:
		return ins
	case protocol.RouteExternal:
		if len(pub) == 0 {
			return ins
		}
		return pub
	}
	return append(ins, pub...)
}

// current is the address in use.
func (r *router) current() candidate {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.list[r.cur]
}

// set replaces the addresses (a learned change), keeping the one in use
// when it is still among them.
func (r *router) set(list []candidate) {
	if len(list) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cur := r.list[r.cur].u.String()
	r.list, r.cur = list, 0
	for i, c := range list {
		if c.u.String() == cur {
			r.cur = i
			return
		}
	}
	r.picked = time.Time{} // the address in use is gone: pick again
}

func (r *router) use(i int) {
	if i != r.cur {
		logrus.WithFields(logrus.Fields{"relay": r.list[i].u.Host, "route": r.list[i].kind, "mode": r.mode}).Info("relay: switched address")
	}
	r.cur = i
}

// ready makes sure an address is chosen before a request: the first
// reachable one on the first request (or after a failure), and the
// preferred one again once per preferEvery while on a fallback. With one
// address it does nothing.
func (r *router) ready(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.list) < 2 {
		return
	}
	now := time.Now()
	switch {
	case r.picked.IsZero():
		r.picked, r.checked = now, now
		for i, c := range r.list {
			if ctx.Err() != nil {
				return
			}
			if r.probe(ctx, c.u) {
				r.use(i)
				return
			}
		}
	case r.cur != 0 && now.Sub(r.checked) >= preferEvery:
		r.checked = now
		if r.probe(ctx, r.list[0].u) {
			r.use(0)
		}
	}
}

// repick makes the next request choose an address again, from the top
// of the list (a new choice of profile).
func (r *router) repick() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cur, r.picked = 0, time.Time{}
}

// failed hears of a request that did not reach the relay: the next request
// picks again (at most once per pickEvery).
func (r *router) failed() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.list) > 1 && time.Since(r.picked) >= pickEvery {
		r.picked = time.Time{}
	}
}

// handshake is a full mutual-TLS handshake with u under cfg, the client's.
func handshake(cfg *tls.Config) func(ctx context.Context, u *url.URL) bool {
	return func(ctx context.Context, u *url.URL) bool {
		ctx, cancel := context.WithTimeout(ctx, probeTimeout)
		defer cancel()
		c := cfg.Clone()
		c.ServerName = u.Hostname()
		host, port := u.Hostname(), u.Port()
		if port == "" {
			port = "443"
		}
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: probeTimeout}, Config: c}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err != nil {
			logrus.WithError(err).WithField("relay", u.Host).Debug("relay: address not reachable")
			return false
		}
		_ = conn.Close()
		return true
	}
}

// Route is the route in use (RouteInternal or RouteExternal) and the
// configured mode.
func (c *Client) Route() (inUse, mode string) {
	return c.routes.current().kind, c.routes.mode
}

// ConnProfileInUse is the connection profile in use (N2): its id and name,
// or "" when the address in use is none of the relay's profiles.
func (c *Client) ConnProfileInUse() (id, name string) {
	cur := c.routes.current()
	return cur.profile, cur.name
}

// RouteText is the route as --status, --doctor and the TUI show it:
// "internal (auto)", "external (operator choice)"; with connection profiles
// (N2) "LAN (auto)", "VPN (chosen)", "External (LAN cannot be reached)",
// "LAN (chosen, no fallback)".
func (c *Client) RouteText() string {
	inUse, mode := c.Route()
	if id, name := c.ConnProfileInUse(); id != "" || c.profilesInUse() {
		if name == "" {
			name = "the enrolment address"
		}
		if v := c.ConnView(); v.Trying != "" { // N5
			return name + " (this run only)"
		}
		st := c.State()
		chosen := profileByID(st.Profiles, st.ConnProfile)
		switch {
		case chosen == nil:
			return name + " (auto)"
		case chosen.ID != id:
			return name + " (" + chosen.Name + " cannot be reached)"
		case st.ConnNoFallback:
			return name + " (chosen, no fallback)"
		}
		return name + " (chosen)"
	}
	switch mode {
	case protocol.RouteExternal:
		return inUse + " (operator choice)"
	case protocol.RouteInternal:
		return inUse + " (forced)"
	}
	return inUse + " (auto)"
}

// candidates is this client's address list from its options and state:
// the relay's connection profiles when it advertised them and client.toml
// overrides no address (N2), else the D28 internal and public addresses.
func candidates(o Options, st *State) []candidate {
	if o.URL == "" && o.PublicURL == "" {
		if list := profileCandidates(st, o.Route); len(list) > 0 {
			return list
		}
	}
	internal := []string{st.RelayURL, st.InternalURL}
	if o.URL != "" {
		internal = []string{o.URL}
	}
	public := st.PublicURL
	if o.PublicURL != "" {
		public = o.PublicURL
	}
	return RouteURLs(internal, public, o.Route)
}

// endpointURL is a host:port the relay advertised as an https:// URL; ""
// for none.
func endpointURL(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" || strings.ContainsAny(hostport, "/@?# ") {
		return ""
	}
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		return ""
	}
	return "https://" + hostport
}

// learn records the relay's advertised addresses (a check-in reply) in
// state.json when they changed, and uses them from the next request.
func (c *Client) learn(ep *protocol.RelayEndpoint) {
	if ep == nil {
		return
	}
	in, pub := endpointURL(ep.Internal), endpointURL(ep.Public)
	c.stateM.Lock()
	if c.state.InternalURL == in && c.state.PublicURL == pub && reflect.DeepEqual(c.state.Profiles, ep.Profiles) {
		c.stateM.Unlock()
		return
	}
	st := *c.state
	st.InternalURL, st.PublicURL, st.Profiles = in, pub, ep.Profiles // N2
	if err := SaveState(c.paths, &st); err != nil {
		c.stateM.Unlock()
		logrus.WithError(err).Warn("relay: could not record the relay's addresses")
		return
	}
	c.state = &st
	c.stateM.Unlock()
	logrus.WithFields(logrus.Fields{"internal": in, "public": pub}).Info("relay: learned the relay's addresses")
	c.routes.set(c.listFor(&st))
}

// ---------------------------------------------------------------- N2

// profileCandidates is the address list from the relay's connection
// profiles (in the relay's order), or nil when it advertised none:
//
//   - a chosen profile comes first; with no fallback it is the only one;
//   - with none chosen, [relay] route still applies: internal keeps the
//     internal profiles, external the external ones (the internal ones
//     when there are none);
//   - the address this machine enrolled through comes last, as a last
//     resort, unless it is already in the list, the choice allows no
//     fallback, or the route is external.
func profileCandidates(st *State, route string) []candidate {
	var all []candidate
	for _, p := range st.Profiles {
		raw := endpointURL(p.RelayAddr)
		u, err := url.Parse(raw)
		if raw == "" || err != nil {
			continue
		}
		kind := p.Kind
		if kind != protocol.RouteExternal {
			kind = protocol.RouteInternal
		}
		all = append(all, candidate{u: u, kind: kind, profile: p.ID, name: p.Name})
	}
	if len(all) == 0 {
		return nil
	}
	chosen := -1
	for i, c := range all {
		if st.ConnProfile != "" && c.profile == st.ConnProfile {
			chosen = i
		}
	}
	var list []candidate
	switch {
	case chosen >= 0 && st.ConnNoFallback:
		return []candidate{all[chosen]}
	case chosen >= 0:
		list = append(list, all[chosen])
		list = append(list, all[:chosen]...)
		list = append(list, all[chosen+1:]...)
	default:
		var ins, exts []candidate
		for _, c := range all {
			if c.kind == protocol.RouteExternal {
				exts = append(exts, c)
			} else {
				ins = append(ins, c)
			}
		}
		switch RouteMode(route) {
		case protocol.RouteInternal:
			list = ins
		case protocol.RouteExternal:
			if len(exts) > 0 {
				return exts // the operator's "we are external": no internal last resort
			}
			list = ins
		default:
			list = all
		}
	}
	if u, err := url.Parse(strings.TrimRight(st.RelayURL, "/")); err == nil && u.Scheme == "https" && u.Host != "" {
		seen := false
		for _, c := range list {
			seen = seen || strings.EqualFold(c.u.Host, u.Host)
		}
		if !seen {
			list = append(list, candidate{u: u, kind: protocol.RouteInternal})
		}
	}
	return list
}

// profilesInUse reports whether the address list is the relay's profiles.
func (c *Client) profilesInUse() bool {
	c.routes.mu.Lock()
	defer c.routes.mu.Unlock()
	for _, cand := range c.routes.list {
		if cand.profile != "" {
			return true
		}
	}
	return false
}

func profileByID(list []protocol.ConnectionProfile, id string) *protocol.ConnectionProfile {
	if id == "" {
		return nil
	}
	for i := range list {
		if list[i].ID == id {
			return &list[i]
		}
	}
	return nil
}

// ErrConnLocked is a choice the console locked (N3).
var ErrConnLocked = errors.New("the console has locked this machine's connection profile")

// SetConnProfile chooses this machine's connection profile: an id the
// relay advertised, or "" for automatic; noFallback keeps it on that one
// even when it cannot be reached. It is saved in state.json and used from
// the next request.
func (c *Client) SetConnProfile(id string, noFallback bool) error {
	c.stateM.Lock()
	if c.state.ConnLockedBy != "" {
		c.stateM.Unlock()
		return ErrConnLocked
	}
	if id != "" && profileByID(c.state.Profiles, id) == nil {
		var ids []string
		for _, p := range c.state.Profiles {
			ids = append(ids, p.ID)
		}
		c.stateM.Unlock()
		if len(ids) == 0 {
			return errors.New("the relay has advertised no connection profiles yet: run mghagent --status to check in, with a relay that has them")
		}
		return fmt.Errorf("no connection profile %q: the relay has %s", id, strings.Join(ids, ", "))
	}
	st := *c.state
	st.ConnProfile, st.ConnNoFallback = id, noFallback && id != ""
	c.trying = "" // a real choice ends a try (N5)
	if err := SaveState(c.paths, &st); err != nil {
		c.stateM.Unlock()
		return fmt.Errorf("record the connection profile: %w", err)
	}
	c.state = &st
	c.stateM.Unlock()
	logrus.WithFields(logrus.Fields{"profile": id, "no_fallback": st.ConnNoFallback}).Info("relay: connection profile chosen")
	c.routes.set(c.listFor(&st))
	c.routes.repick()
	return nil
}

// applyConn applies the console's connection profile setting from a
// check-in or enrolment reply (N3): once per revision, so a choice made on
// this machine afterwards stands, and at every reply while it is locked.
// A setting the console no longer manages only lifts the lock.
func (c *Client) applyConn(set *protocol.ConnSetting) {
	if set == nil {
		return
	}
	c.stateM.Lock()
	st := *c.state
	locked := ""
	if set.Managed && set.Locked {
		locked = "console"
	}
	if set.Managed && (set.Rev != st.ConnRev || set.Locked) {
		st.ConnProfile, st.ConnNoFallback = set.Profile, set.NoFallback && set.Profile != ""
	}
	st.ConnLockedBy, st.ConnRev = locked, set.Rev
	old := *c.state
	if st.ConnProfile == old.ConnProfile && st.ConnNoFallback == old.ConnNoFallback && st.ConnLockedBy == old.ConnLockedBy && st.ConnRev == old.ConnRev {
		c.stateM.Unlock()
		return
	}
	if err := SaveState(c.paths, &st); err != nil {
		c.stateM.Unlock()
		logrus.WithError(err).Warn("relay: could not record the console's connection profile")
		return
	}
	c.state = &st
	c.stateM.Unlock()
	if st.ConnProfile != old.ConnProfile || st.ConnNoFallback != old.ConnNoFallback {
		logrus.WithFields(logrus.Fields{"profile": st.ConnProfile, "no_fallback": st.ConnNoFallback, "locked": locked != ""}).Info("relay: the console set the connection profile")
		c.routes.set(c.listFor(&st))
		c.routes.repick()
	}
}
