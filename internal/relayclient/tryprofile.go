package relayclient

// The TUI's view of the connection profiles, a reachability check per
// profile, and "try another network once": a profile used for this run
// only, without changing the stored choice — allowed even when the console
// locked it, so a machine whose locked address died can still reach the
// relay and receive the corrected setting.

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/mpaishon/mghclient/internal/protocol"
)

// ConnView is the connection profiles as the TUI shows them.
type ConnView struct {
	Profiles   []protocol.ConnectionProfile
	Chosen     string // the stored choice; "" = automatic
	NoFallback bool
	LockedBy   string // "console" or ""
	InUse      string // the profile of the address in use; "" for none of them
	Trying     string // the profile tried for this run only; "" for none
	// Overridden: client.toml's [relay] url or public_url replaces the
	// relay's addresses, so the profiles are not used.
	Overridden bool
}

// ConnView is the connection profiles, the choice and the one in use.
func (c *Client) ConnView() ConnView {
	st := c.State()
	inUse, _ := c.ConnProfileInUse()
	c.stateM.Lock()
	trying := c.trying
	c.stateM.Unlock()
	return ConnView{
		Profiles: st.Profiles, Chosen: st.ConnProfile, NoFallback: st.ConnNoFallback, LockedBy: st.ConnLockedBy,
		InUse: inUse, Trying: trying, Overridden: c.opts.URL != "" || c.opts.PublicURL != "",
	}
}

// listFor is the address list for st: the profile being tried alone, or
// the usual candidates.
func (c *Client) listFor(st *State) []candidate {
	c.stateM.Lock()
	trying := c.trying
	c.stateM.Unlock()
	if trying != "" {
		for _, cand := range profileCandidates(&State{Profiles: st.Profiles, ConnProfile: trying, ConnNoFallback: true}, "") {
			return []candidate{cand}
		}
	}
	return candidates(c.opts, st)
}

// TryConnProfile uses profile id for this run only ("" stops trying): the
// stored choice, and a console lock, are left as they are. The relay sees
// it as the profile in use at the next check-in.
func (c *Client) TryConnProfile(id string) error {
	st := c.State()
	if id != "" && profileByID(st.Profiles, id) == nil {
		return fmt.Errorf("no connection profile %q", id)
	}
	if id != "" && (c.opts.URL != "" || c.opts.PublicURL != "") {
		return errors.New("[relay] url or public_url in client.toml replaces the relay's addresses: remove them to use a profile")
	}
	c.stateM.Lock()
	c.trying = id
	c.stateM.Unlock()
	logrus.WithField("profile", id).Info("relay: trying a connection profile for this run")
	c.routes.set(c.listFor(&st))
	c.routes.repick()
	return nil
}

// ProbeConnProfiles checks every profile's address with a full mutual-TLS
// handshake (4 s each, in parallel): whether this machine can reach the
// relay there now.
func (c *Client) ProbeConnProfiles(ctx context.Context) map[string]bool {
	st := c.State()
	out := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range st.Profiles {
		u, err := url.Parse(endpointURL(p.RelayAddr))
		if err != nil || u.Host == "" {
			out[p.ID] = false
			continue
		}
		wg.Add(1)
		go func(id string, u *url.URL) {
			defer wg.Done()
			ok := c.routes.probe(ctx, u)
			mu.Lock()
			out[id] = ok
			mu.Unlock()
		}(p.ID, u)
	}
	wg.Wait()
	return out
}
