package relayclient

// r2-C: the route (D28).

import (
	"context"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mpaishon/mghclient/internal/protocol"
	"github.com/mpaishon/mghclient/internal/relayclient/relaytest"
)

func hosts(list []candidate) string {
	var out []string
	for _, c := range list {
		out = append(out, c.kind+"="+c.u.Host)
	}
	return strings.Join(out, ",")
}

func TestRouteURLs(t *testing.T) {
	in := []string{"https://192.0.2.13:9444", "https://192.0.2.12:9444", "https://192.0.2.13:9444/"}
	pub := "https://relay.example.com:9444"
	for _, c := range []struct {
		mode, public, want string
	}{
		{"", pub, "internal=192.0.2.13:9444,internal=192.0.2.12:9444,external=relay.example.com:9444"},
		{protocol.RouteAuto, "", "internal=192.0.2.13:9444,internal=192.0.2.12:9444"},
		{protocol.RouteInternal, pub, "internal=192.0.2.13:9444,internal=192.0.2.12:9444"},
		{protocol.RouteExternal, pub, "external=relay.example.com:9444"},
		{protocol.RouteExternal, "", "internal=192.0.2.13:9444,internal=192.0.2.12:9444"}, // nothing public known yet
		{protocol.RouteAuto, "http://plain:80", "internal=192.0.2.13:9444,internal=192.0.2.12:9444"},
	} {
		if got := hosts(RouteURLs(in, c.public, c.mode)); got != c.want {
			t.Errorf("mode %q public %q: %s, want %s", c.mode, c.public, got, c.want)
		}
	}
}

// fakeProbe answers reachability from a set the test changes.
type fakeProbe struct {
	up    map[string]bool
	calls []string
}

func (f *fakeProbe) probe(_ context.Context, u *url.URL) bool {
	f.calls = append(f.calls, u.Host)
	return f.up[u.Host]
}

func TestRouterAutoFallsBackAndReturns(t *testing.T) {
	f := &fakeProbe{up: map[string]bool{"relay.example.com:9444": true}}
	r := &router{mode: protocol.RouteAuto, list: RouteURLs([]string{"https://192.0.2.12:9444"}, "https://relay.example.com:9444", ""), probe: f.probe}
	ctx := context.Background()

	r.ready(ctx)
	if c := r.current(); c.kind != protocol.RouteExternal {
		t.Fatalf("internal down: using %s", hosts([]candidate{c}))
	}
	// Within the minute the preferred address is not probed again.
	f.calls = nil
	f.up["192.0.2.12:9444"] = true
	r.ready(ctx)
	if len(f.calls) != 0 || r.current().kind != protocol.RouteExternal {
		t.Fatalf("re-probed within a minute: %v", f.calls)
	}
	// After it, the internal address is tried again and wins.
	r.mu.Lock()
	r.checked = time.Now().Add(-preferEvery)
	r.mu.Unlock()
	r.ready(ctx)
	if r.current().kind != protocol.RouteInternal {
		t.Fatal("the internal address is back but not used")
	}
	// On the preferred address nothing is probed per request.
	f.calls = nil
	r.ready(ctx)
	if len(f.calls) != 0 {
		t.Errorf("probed on the preferred address: %v", f.calls)
	}
	// A failed request makes the next one pick again (once pickEvery passed).
	f.up["192.0.2.12:9444"] = false
	r.mu.Lock()
	r.picked = time.Now().Add(-pickEvery)
	r.mu.Unlock()
	r.failed()
	r.ready(ctx)
	if r.current().kind != protocol.RouteExternal {
		t.Error("after a failure the client did not fall back")
	}
}

func TestRouterSingleAddressNeverProbes(t *testing.T) {
	f := &fakeProbe{}
	r := &router{mode: protocol.RouteExternal, list: RouteURLs([]string{"https://192.0.2.12:9444"}, "https://relay.example.com:9444", protocol.RouteExternal), probe: f.probe}
	r.ready(context.Background())
	r.failed()
	r.ready(context.Background())
	if len(f.calls) != 0 || r.current().kind != protocol.RouteExternal {
		t.Errorf("calls %v, current %+v", f.calls, r.current())
	}
}

func TestRouterSetKeepsTheAddressInUse(t *testing.T) {
	r := &router{mode: protocol.RouteAuto, list: RouteURLs([]string{"https://a:1"}, "https://pub:1", ""), cur: 1, picked: time.Now()}
	r.set(RouteURLs([]string{"https://a:1", "https://b:1"}, "https://pub:1", ""))
	if r.current().u.Host != "pub:1" {
		t.Errorf("in use after a change: %s", r.current().u.Host)
	}
	r.set(RouteURLs([]string{"https://a:1"}, "https://newpub:1", ""))
	if !r.picked.IsZero() {
		t.Error("the address in use disappeared but no new pick is due")
	}
}

func TestEndpointURL(t *testing.T) {
	for in, want := range map[string]string{
		"relay.example.com:9444": "https://relay.example.com:9444",
		"[fd00::1]:9444":         "https://[fd00::1]:9444",
		"":                       "",
		"relay.example.com":      "",
		"x/y:1":                  "",
	} {
		if got := endpointURL(in); got != want {
			t.Errorf("endpointURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWANStatusErrorIsClear(t *testing.T) {
	err := &StatusError{Code: 403, Message: protocol.WANRefusedMessage, WAN: protocol.WANOffClient}
	if !strings.Contains(err.Error(), protocol.WANRefusedMessage) || strings.Contains(err.Error(), "revoked") {
		t.Errorf("%v", err)
	}
}

// A real relay: the internal address is dead, so auto falls back to the
// public one after a full mutual-TLS handshake, and reports it.
func TestAutoFallsBackToThePublicAddress(t *testing.T) {
	s := relaytest.New(t, fakeData())
	dir, res := enroll(t, s)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := "https://" + ln.Addr().String()
	ln.Close()
	c, err := New(Options{StateDir: dir, URL: dead, PublicURL: res.RelayURL, Version: "v2026.10.27"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.WhoAmI(context.Background()); err != nil {
		t.Fatalf("whoami through the fallback: %v", err)
	}
	if inUse, mode := c.Route(); inUse != protocol.RouteExternal || mode != protocol.RouteAuto || c.URL() != res.RelayURL {
		t.Errorf("route %s/%s via %s", inUse, mode, c.URL())
	}
	if _, err := New(Options{StateDir: dir, Route: "sideways"}); err == nil {
		t.Error("an unknown route was accepted")
	}
}
