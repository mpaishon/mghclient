package relayclient

// N2: connection profiles on the client.

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/mpaishon/mghclient/internal/protocol"
	"github.com/mpaishon/mghclient/internal/relayclient/relaytest"
)

func profileHosts(list []candidate) string {
	var out []string
	for _, c := range list {
		id := c.profile
		if id == "" {
			id = "-"
		}
		out = append(out, id+"="+c.u.Host)
	}
	return strings.Join(out, ",")
}

var threeProfiles = []protocol.ConnectionProfile{
	{ID: "lan", Name: "LAN", Kind: protocol.RouteInternal, RelayAddr: "192.0.2.12:9444", Order: 1},
	{ID: "vpn", Name: "VPN", Kind: protocol.RouteInternal, RelayAddr: "198.51.100.5:9444", Order: 2},
	{ID: "external", Name: "External", Kind: protocol.RouteExternal, RelayAddr: "relay.example.com:443", Order: 3},
}

// The order a client tries the relay's profiles in.
func TestProfileCandidates(t *testing.T) {
	const all = "lan=192.0.2.12:9444,vpn=198.51.100.5:9444,external=relay.example.com:443"
	for _, c := range []struct {
		name, route, chosen string
		only                bool
		relayURL            string
		want                string
	}{
		{"auto, enrolled by name", "", "", false, "https://relay-lan.example:9444", all + ",-=relay-lan.example:9444"},
		{"auto, enrolled at a profile's address", "", "", false, "https://192.0.2.12:9444", all},
		{"route internal", protocol.RouteInternal, "", false, "https://relay-lan.example:9444", "lan=192.0.2.12:9444,vpn=198.51.100.5:9444,-=relay-lan.example:9444"},
		{"route external", protocol.RouteExternal, "", false, "https://relay-lan.example:9444", "external=relay.example.com:443"},
		{"chosen", "", "vpn", false, "https://relay-lan.example:9444", "vpn=198.51.100.5:9444,lan=192.0.2.12:9444,external=relay.example.com:443,-=relay-lan.example:9444"},
		{"chosen beats the route", protocol.RouteExternal, "lan", false, "https://relay-lan.example:9444", "lan=192.0.2.12:9444,vpn=198.51.100.5:9444,external=relay.example.com:443,-=relay-lan.example:9444"},
		{"chosen, only", "", "vpn", true, "https://relay-lan.example:9444", "vpn=198.51.100.5:9444"},
		{"chosen but gone", "", "site-b", false, "https://192.0.2.12:9444", all},
	} {
		st := &State{RelayURL: c.relayURL, Profiles: threeProfiles, ConnProfile: c.chosen, ConnNoFallback: c.only}
		if got := profileHosts(candidates(Options{Route: c.route}, st)); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
	// client.toml overrides an address: the D28 list, as before.
	st := &State{RelayURL: "https://relay-lan.example:9444", Profiles: threeProfiles, ConnProfile: "vpn"}
	if got := profileHosts(candidates(Options{URL: "https://203.0.113.5:9444"}, st)); got != "-=203.0.113.5:9444" {
		t.Errorf("[relay] url: %s", got)
	}
	// An older relay advertised none: the D28 list.
	st = &State{RelayURL: "https://relay-lan.example:9444", PublicURL: "https://relay.example.com:443"}
	if got := profileHosts(candidates(Options{}, st)); got != "-=relay-lan.example:9444,-=relay.example.com:443" {
		t.Errorf("no profiles: %s", got)
	}
}

// End to end: the profiles come with the enrolment; a chosen profile that
// cannot be reached falls back unless --only; the choice is kept in
// state.json; a locked choice cannot be changed here.
func TestChoosingAConnectionProfile(t *testing.T) {
	s := relaytest.New(t, fakeData())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()
	s.SetData(func(d *relaytest.Data) {
		d.ConnProfiles = []protocol.ConnectionProfile{
			{ID: "lan", Name: "LAN", Kind: protocol.RouteInternal, RelayAddr: "127.0.0.1:" + s.RelayPort(), Order: 1},
			{ID: "vpn", Name: "VPN", Kind: protocol.RouteInternal, RelayAddr: dead, Order: 2},
		}
	})
	dir, _ := enroll(t, s)
	c := newClient(t, dir)
	ctx := context.Background()
	if len(c.State().Profiles) != 2 {
		t.Fatalf("the enrolment did not keep the profiles: %+v", c.State().Profiles)
	}
	if _, err := c.WhoAmI(ctx); err != nil {
		t.Fatal(err)
	}
	if got := c.RouteText(); got != "LAN (auto)" {
		t.Errorf("auto: %q", got)
	}

	if err := c.SetConnProfile("vpn", false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.WhoAmI(ctx); err != nil {
		t.Fatalf("no fallback from an unreachable VPN: %v", err)
	}
	if id, _ := c.ConnProfileInUse(); id != "lan" || c.RouteText() != "LAN (VPN cannot be reached)" {
		t.Errorf("fallback: %s %q", id, c.RouteText())
	}

	if err := c.SetConnProfile("vpn", true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.WhoAmI(ctx); err == nil {
		t.Error("--only VPN still reached the relay through LAN")
	}
	again := newClient(t, dir)
	if st := again.State(); st.ConnProfile != "vpn" || !st.ConnNoFallback {
		t.Errorf("the choice was not kept: %+v", st)
	}
	if got := again.RouteText(); got != "VPN (chosen, no fallback)" {
		t.Errorf("only: %q", got)
	}

	if err := c.SetConnProfile("site-b", false); err == nil || !strings.Contains(err.Error(), "lan, vpn") {
		t.Errorf("an unknown profile: %v", err)
	}
	if err := c.SetConnProfile("", true); err != nil || c.State().ConnNoFallback {
		t.Errorf("auto with only: %v %+v", err, c.State())
	}

	st := c.State()
	st.ConnLockedBy = "console"
	if err := SaveState(Paths{Dir: dir}, &st); err != nil {
		t.Fatal(err)
	}
	if err := newClient(t, dir).SetConnProfile("lan", false); !errors.Is(err, ErrConnLocked) {
		t.Errorf("a locked choice changed: %v", err)
	}
}

// N3: the console's setting is applied once per revision, so a choice made
// here afterwards stands; while locked it is enforced at every reply and
// cannot be changed here; unmanaged, it only lifts the lock.
func TestConsoleConnSetting(t *testing.T) {
	s := relaytest.New(t, fakeData())
	s.SetData(func(d *relaytest.Data) { d.ConnProfiles = threeProfiles })
	dir, _ := enroll(t, s)
	c := newClient(t, dir)
	st := func() State { return c.State() }

	c.applyConn(&protocol.ConnSetting{Managed: true, Profile: "vpn", Rev: 1})
	if st().ConnProfile != "vpn" || st().ConnLockedBy != "" || st().ConnRev != 1 {
		t.Fatalf("applied %+v", st())
	}
	if err := c.SetConnProfile("lan", false); err != nil {
		t.Fatal(err)
	}
	c.applyConn(&protocol.ConnSetting{Managed: true, Profile: "vpn", Rev: 1})
	if st().ConnProfile != "lan" {
		t.Error("the same revision overrode the machine's own choice")
	}
	c.applyConn(&protocol.ConnSetting{Managed: true, Profile: "external", NoFallback: true, Locked: true, Rev: 2})
	if st().ConnProfile != "external" || !st().ConnNoFallback || st().ConnLockedBy != "console" {
		t.Fatalf("locked %+v", st())
	}
	if err := c.SetConnProfile("lan", false); !errors.Is(err, ErrConnLocked) {
		t.Errorf("changed while locked: %v", err)
	}
	if profileHosts(c.routes.list) != "external=relay.example.com:443" {
		t.Errorf("the router did not follow: %s", profileHosts(c.routes.list))
	}
	// Locked, it is enforced again even at the same revision.
	forced := st()
	forced.ConnProfile = "lan"
	if err := SaveState(Paths{Dir: dir}, &forced); err != nil {
		t.Fatal(err)
	}
	c = newClient(t, dir)
	c.applyConn(&protocol.ConnSetting{Managed: true, Profile: "external", NoFallback: true, Locked: true, Rev: 2})
	if st().ConnProfile != "external" {
		t.Error("a locked setting was not enforced")
	}
	c.applyConn(&protocol.ConnSetting{Managed: false, Rev: 3})
	if st().ConnLockedBy != "" || st().ConnProfile != "external" {
		t.Errorf("unmanaged: %+v", st())
	}
	if err := c.SetConnProfile("lan", false); err != nil {
		t.Errorf("still locked: %v", err)
	}
	c.applyConn(nil) // an older relay
	if st().ConnProfile != "lan" {
		t.Error("no setting changed the choice")
	}
}

// N4: an install line's setting arrives with the enrolment.
func TestEnrolmentCarriesTheConnSetting(t *testing.T) {
	s := relaytest.New(t, fakeData())
	s.SetData(func(d *relaytest.Data) {
		d.ConnProfiles = threeProfiles
		d.Conn = &protocol.ConnSetting{Managed: true, Profile: "vpn", NoFallback: true, Locked: true, Rev: 7}
	})
	dir, _ := enroll(t, s)
	st := newClient(t, dir).State()
	if st.ConnProfile != "vpn" || !st.ConnNoFallback || st.ConnLockedBy != "console" || st.ConnRev != 7 {
		t.Errorf("state %+v", st)
	}
}
