package protocol

// WAN access; added 2026-10-29.
//
// A connection to the [relay] listener is external when its TCP peer is not
// a private, loopback or link-local address, or when it arrives from one of
// [relay] proxy_addrs (NPM's stream: a TCP passthrough carries no client
// address, and LAN clients reach the relay directly). An external
// connection is let in only while the household's "Allow clients from
// outside" switch is on (refused before the handshake otherwise) and the
// client's own "Allow WAN" is on (refused with 403 on every request
// otherwise).

// Routes: which relay address a client uses ([relay] route in client.toml).
const (
	// RouteAuto tries the internal address first (a full mutual-TLS
	// handshake, 4 s), falls back to the public one, and tries the internal
	// one again at most once a minute.
	RouteAuto = "auto"
	// RouteInternal uses the internal address only.
	RouteInternal = "internal"
	// RouteExternal is the operator's "we are external": the public address
	// only.
	RouteExternal = "external"
)

// RouteModes are the values of [relay] route.
var RouteModes = []string{RouteAuto, RouteInternal, RouteExternal}

// WANRefusedMessage is the 403 an external request gets while WAN access is
// off for its client.
const WANRefusedMessage = "WAN access is off for this client"

// HeaderWANRefused marks that 403, so a client can tell it from a
// revocation: WANOffClient (this client's Allow WAN is off) or
// WANOffHousehold (Allow clients from outside is off).
const HeaderWANRefused = "X-Relay-WAN-Refused"

// Values of HeaderWANRefused.
const (
	WANOffClient    = "client"
	WANOffHousehold = "household"
)

// Audit actions.
const (
	AuditConnection = "connection_change" // the household's connection settings changed
	AuditWANRefused = "wan_refused"       // an external request was refused
)

// Connection is GET /admin/connection: the outside-access switches and the
// relay's addresses, as Settings → Connection shows them.
type Connection struct {
	// AllowOutside is the effective master switch: the household setting,
	// or forced on by [relay] outside.
	AllowOutside bool `json:"allow_outside"`
	// OutsideLocked: [relay] outside (MGHRELAY_RELAY_OUTSIDE) is true, so
	// the switch is on and the console cannot turn it off.
	OutsideLocked bool `json:"outside_locked"`
	// EnrollOutside is [enroll] outside: enrolment from outside the local
	// network, a separate machine setting (shown here, changed in Settings
	// → Machine).
	EnrollOutside bool `json:"enroll_outside"`
	// ProxyAddrs is the effective [relay] proxy_addrs list; ProxyFromWeb
	// says it is [web] trusted_proxies because proxy_addrs is empty.
	ProxyAddrs   []string `json:"proxy_addrs"`
	ProxyFromWeb bool     `json:"proxy_from_web,omitempty"`
	// InternalAddr is the relay_internal_addr setting ("" = derived);
	// InternalEffective is what clients are told.
	InternalAddr      string `json:"internal_addr"`
	InternalEffective string `json:"internal_effective"`
	// PublicAddr is relay_public_addr, host:port; "" when there is none.
	PublicAddr string `json:"public_addr"`
	// RelayNames are the names on the relay certificate ([relay] san).
	RelayNames []string `json:"relay_names"`
	// Port is the [relay] listener's port.
	Port string `json:"port"`
	// Warnings are problems to fix, each a sentence (the public host not on
	// the relay certificate, say).
	Warnings []string `json:"warnings"`
	// WANClients is how many unrevoked clients have Allow WAN on.
	WANClients int `json:"wan_clients"`
	// AddressesHidden: clients have been seen arriving from the container's
	// own gateway (Docker bridge networking), so external cannot be judged;
	// the master switch cannot be turned on until the relay runs with host
	// networking.
	AddressesHidden bool `json:"addresses_hidden,omitempty"`
	// Profiles are the connection profiles as kept (RelayAddr may be
	// empty: derived); ProfilesKept is false while they are only the
	// addresses, not yet saved as a list.
	Profiles     []ConnectionProfile `json:"profiles"`
	ProfilesKept bool                `json:"profiles_kept"`
}

// ConnectionUpdate is PUT /admin/connection: only the fields to change.
type ConnectionUpdate struct {
	AllowOutside *bool   `json:"allow_outside,omitempty"`
	InternalAddr *string `json:"internal_addr,omitempty"`
	PublicAddr   *string `json:"public_addr,omitempty"`
	// Profiles replaces the whole list. InternalAddr and PublicAddr
	// still work: they edit the first internal and external profile.
	Profiles *[]ConnectionProfile `json:"profiles,omitempty"`
}
