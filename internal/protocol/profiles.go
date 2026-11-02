package protocol

// Connection profiles; added
// 2026-10-30.
//
// A connection profile is one network a client may reach the relay from —
// LAN, VPN, External — with the relay's address there. The household keeps
// the list (the connection_profiles setting); the relay advertises it in
// every enrolment and check-in reply, and puts every profile's host on the
// relay certificate. A profile never grants access: the relay still judges
// internal or external from the TCP peer, though an internal profile's
// networks count as internal (a VPN's 100.64.0.0/10, say).

// ConnectionProfile is one network clients may reach the relay from.
type ConnectionProfile struct {
	// ID is stable and lowercase ("lan", "vpn", "external"): what a client
	// stores and what the console sets.
	ID string `json:"id"`
	// Name is shown in the console and the client TUI.
	Name string `json:"name"`
	// Kind is RouteInternal or RouteExternal: which side of [relay] route
	// it serves, and which of RelayEndpoint.Internal / Public it fills for
	// clients that predate profiles.
	Kind string `json:"kind"`
	// RelayAddr is the mutual-TLS listener on this network, host[:port]
	// (the [relay] listener's port when it names none). Stored, it may be
	// empty on an internal profile: derived from [relay] san. Advertised, it
	// is always host:port.
	RelayAddr string `json:"relay_addr"`
	// ConsoleURL is the console on this network, https://host[:port], for
	// install lines and enrolment; "" is [web] public_url.
	ConsoleURL string `json:"console_url,omitempty"`
	// Networks are CIDRs the relay treats as internal (an internal profile
	// only). Never advertised to clients.
	Networks []string `json:"networks,omitempty"`
	// Order is the fallback order, 1 first.
	Order int `json:"order"`
}

// Connection profile IDs the relay makes from the addresses when no
// list is kept. (Not ProfileExternal: that is an access profile.)
const (
	ConnLAN      = "lan"
	ConnExternal = "external"
)

// MaxConnectionProfiles bounds the household's list.
const MaxConnectionProfiles = 16

// ----------------------------------------------------------------

// ConnSetting is the console's connection profile setting for one client.
// Managed false: the console leaves the choice to the machine. Rev changes
// whenever the console changes it: a client applies a setting once per Rev,
// so a choice made on the machine afterwards stands — unless Locked, which
// the client enforces at every check-in and refuses to change locally.
type ConnSetting struct {
	Managed    bool   `json:"managed"`
	Profile    string `json:"profile,omitempty"` // "" = automatic
	NoFallback bool   `json:"no_fallback,omitempty"`
	Locked     bool   `json:"locked,omitempty"`
	Rev        int64  `json:"rev,omitempty"`
}

// ConnSettingRequest is PUT /admin/clients/:id/connection.
type ConnSettingRequest struct {
	Managed    bool   `json:"managed"`
	Profile    string `json:"profile,omitempty"`
	NoFallback bool   `json:"no_fallback,omitempty"`
	Locked     bool   `json:"locked,omitempty"`
}

// CommandCheckIn asks a connected client to check in now: the console
// changed something it learns from the check-in reply (its connection
// profile setting). It answers PlanDone.
const CommandCheckIn = "checkin"

// PlanDone answers a CommandCheckIn.
const PlanDone = "done"

// AuditClientConn: the console set a client's connection profile.
const AuditClientConn = "client_connection"
