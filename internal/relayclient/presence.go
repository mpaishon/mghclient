package relayclient

// Check-in and the live channel, and presence.json, the
// client's record of when it last checked in and what its watched repos
// last fetched.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/mpaishon/mghclient/internal/protocol"
)

// PresenceFile is the check-in record in the state folder.
const PresenceFile = "presence.json"

// Presence names presence.json.
func (p Paths) Presence() string { return filepath.Join(p.Dir, PresenceFile) }

// WatchState is what one watched repository last came to here.
type WatchState struct {
	Tag string    `json:"tag,omitempty"` // the newest published tag fetched (or found without a build for this platform)
	At  time.Time `json:"at"`
	// Error is why the last attempt failed; the tag is tried again.
	Error string `json:"error,omitempty"`
	// NoBuild says Tag has no build for this platform: it is not fetched,
	// nor looked at again.
	NoBuild bool `json:"no_build,omitempty"`
	// Reported says the relay has heard of this state at a check-in.
	Reported bool `json:"reported,omitempty"`
}

// PresenceState is presence.json.
type PresenceState struct {
	LastCheckin time.Time             `json:"last_checkin,omitempty"`
	Watched     map[string]WatchState `json:"watched,omitempty"`
	// LastRequest is how the console's last request here went.
	LastRequest string `json:"last_request,omitempty"`
}

// LoadPresence reads presence.json; a missing or damaged one is empty (it
// is a record of work done, rebuilt by doing it).
func LoadPresence(p Paths) PresenceState {
	raw, err := os.ReadFile(p.Presence())
	var st PresenceState
	if err == nil {
		_ = json.Unmarshal(raw, &st)
	}
	if st.Watched == nil {
		st.Watched = map[string]WatchState{}
	}
	return st
}

// SavePresence writes presence.json atomically, 0600.
func SavePresence(p Paths, st PresenceState) error {
	raw, err := json.MarshalIndent(st, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return err
	}
	return writeFile(p.Presence(), raw, 0o600)
}

// CheckIn sends the report (POST /relay/checkin) and returns the relay's
// answer: the watch list.
func (c *Client) CheckIn(ctx context.Context, rep protocol.ClientReport) (protocol.CheckinReply, error) {
	var out protocol.CheckinReply
	// The route in use and the configured mode. The relay's
	// answer carries its addresses; a change is learned below.
	c.routes.ready(ctx)
	rep.Route, rep.RouteMode = c.Route()
	// The connection profile chosen here and the one in use.
	st := c.State()
	rep.ConnProfile, rep.ConnNoFallback, rep.ConnLocked = st.ConnProfile, st.ConnNoFallback, st.ConnLockedBy != ""
	rep.ConnProfileInUse, _ = c.ConnProfileInUse()
	body, err := json.Marshal(rep)
	if err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	resp, err := c.do(ctx, http.MethodPost, protocol.PathCheckin, nil, bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if err := decode(resp.Body, &out); err != nil {
		return out, fmt.Errorf("relay %s%s: %w", c.host(), protocol.PathCheckin, err)
	}
	c.learn(out.Relay)
	c.applyConn(out.Conn)
	return out, nil
}

// pollSlack is how much longer than the relay's hold the client waits.
const pollSlack = 20 * time.Second

// NextCommand holds GET /relay/commands: a Command, or nil when the relay's
// hold passed without one. Holding it is what makes this client
// "connected" to the console.
func (c *Client) NextCommand(ctx context.Context) (*protocol.Command, error) {
	ctx, cancel := context.WithTimeout(ctx, protocol.CommandHold+pollSlack)
	defer cancel()
	resp, err := c.do(ctx, http.MethodGet, protocol.PathCommands, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	var cmd protocol.Command
	if err := decode(resp.Body, &cmd); err != nil {
		return nil, fmt.Errorf("relay %s%s: %w", c.host(), protocol.PathCommands, err)
	}
	if cmd.ID == "" {
		return nil, errors.New("the relay sent a command without an id")
	}
	return &cmd, nil
}

// Ack answers a command with this client's plan.
func (c *Client) Ack(ctx context.Context, id string, ack protocol.CommandAck) error {
	body, err := json.Marshal(ack)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	resp, err := c.do(ctx, http.MethodPost, protocol.PathCommands+"/"+url.PathEscape(id)+protocol.PathCommandAck, nil, bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
