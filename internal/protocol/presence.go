package protocol

// r2-B: client presence (D25), service mode and promote-while-connected
// (D26), and install scripts (D27). A file of its own so the round-2 streams
// merge without touching each other's lines; added 2026-10-29.
//
// After File Cellar's internal/protocol/run.go: a client says how it runs at
// check-in, so the console can tell whether it is the background service
// already and what its "Run as a service" would take — nothing on macOS and
// Linux, no prompt on Windows when the client runs as an administrator, an
// administrator prompt on that machine's screen otherwise.

import "time"

// r2-B: [relay] paths.
const (
	// PathCheckin is POST: a ClientReport in, a CheckinReply out.
	PathCheckin = RelayPrefix + "/checkin"
	// PathCommands is GET: the live channel. The relay holds the request
	// open (CommandHold) and answers 204, or 200 with a Command. A client
	// that holds it is "connected".
	PathCommands = RelayPrefix + "/commands"
	// PathCommandAck is POST PathCommands/<id>/ack with a CommandAck.
	PathCommandAck = "/ack"
)

// CommandHold is how long the relay holds GET /relay/commands open before
// answering 204. The client's own timeout is longer.
const CommandHold = 50 * time.Second

// CheckinEvery is how often a background service checks in.
const CheckinEvery = 60 * time.Second

// Run modes a client reports.
const (
	RunService  = "service"  // under the system's service manager (--run, started by it)
	RunTerminal = "terminal" // --tui
	RunPlain    = "plain"    // any other command, or --run in a terminal
)

// RunModes are the modes a client may report.
var RunModes = []string{RunService, RunTerminal, RunPlain}

// Service states a client reports for the background service on its machine.
const (
	ServiceNotInstalled = "not installed"
	ServiceStopped      = "stopped"
	ServiceRunning      = "running"
	ServiceStarting     = "starting"
	ServiceStopping     = "stopping"
	ServiceUnknown      = "unknown"
)

// ServiceStates are the states a client may report ("" when the system has
// no service manager the client knows).
var ServiceStates = []string{"", ServiceNotInstalled, ServiceStopped, ServiceRunning, ServiceStarting, ServiceStopping, ServiceUnknown}

// ClientReport is what a client says about itself at every check-in (D25).
// Every text is short and free of control characters; the relay refuses one
// that is not.
type ClientReport struct {
	ExePath    string `json:"exe_path,omitempty"`
	InstallDir string `json:"install_dir,omitempty"`
	ConfigPath string `json:"config_path,omitempty"`
	OSUser     string `json:"os_user,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	OS         string `json:"os,omitempty"`
	Arch       string `json:"arch,omitempty"`
	Version    string `json:"version,omitempty"`
	Commit     string `json:"commit,omitempty"`
	// RunMode is RunService, RunTerminal or RunPlain.
	RunMode string `json:"run_mode"`
	// Service is the background service's state on that machine, when it is
	// this client's (or none is installed); one of ServiceStates.
	Service string `json:"service,omitempty"`
	// Admin: it runs as an administrator (Windows: an elevated token;
	// elsewhere root), so it can install the service without asking.
	Admin bool `json:"admin"`
	// Prompt: not an administrator, but on a desktop where Windows can ask
	// for one (UAC): someone at the machine must say yes.
	Prompt bool `json:"prompt"`
	// LastRequest is how the console's last request here went ("run as a
	// service: installed", "… not done: …"); "" when there was none.
	LastRequest string `json:"last_request,omitempty"`
	// Fetched are the watched-repo fetches since the last check-in the
	// relay acknowledged.
	Fetched []WatchFetch `json:"fetched,omitempty"`
	// r2-C: Route is the relay address this client uses now, RouteInternal
	// or RouteExternal; RouteMode is its client.toml [relay] route (auto,
	// internal or external). Both "" from a client older than D28.
	Route     string `json:"route,omitempty"`
	RouteMode string `json:"route_mode,omitempty"`
	// N2: the connection profile chosen on this machine ("" = automatic),
	// whether it stays on it when it cannot be reached, whether the
	// console locked the choice, and the profile in use now ("" when the
	// address in use is none of the relay's profiles: [relay] url, say).
	ConnProfile      string `json:"conn_profile,omitempty"`
	ConnNoFallback   bool   `json:"conn_no_fallback,omitempty"`
	ConnLocked       bool   `json:"conn_locked,omitempty"`
	ConnProfileInUse string `json:"conn_profile_in_use,omitempty"`
}

// WatchFetch is one watched repository's latest fetch, as the client reports
// it: the tag it now has, or why it has not.
type WatchFetch struct {
	Repo  string    `json:"repo"`
	Tag   string    `json:"tag,omitempty"`
	At    time.Time `json:"at"`
	Error string    `json:"error,omitempty"`
}

// WatchTarget is one repository a client watches. LatestTag is the newest
// published release the relay knows for it, visible to the client; the
// client lists releases only when it differs from what it has.
type WatchTarget struct {
	Repo      string `json:"repo"`
	LatestTag string `json:"latest_tag,omitempty"`
}

// CheckinReply is the relay's answer to a check-in.
type CheckinReply struct {
	// Watch is the client's watch list, set in the console (D26).
	Watch []WatchTarget `json:"watch"`
	// Every is how often a background service should check in, seconds.
	Every int `json:"every"`
	// r2-C: Relay is where the relay is, internally and publicly (D28), so
	// a client learns a changed address at its next check-in.
	Relay *RelayEndpoint `json:"relay,omitempty"`
	// Update is an "Update now" the console queued while this client was
	// not connected (D29): a CommandUpdate it answers through the ack route
	// like one sent live. Repeated at every check-in until it is answered.
	Update *Command `json:"update,omitempty"`
	// N3: Conn is the console's connection profile setting for this
	// client; nil from a relay without one.
	Conn *ConnSetting `json:"conn,omitempty"`
}

// Command kinds.
const (
	// CommandService tells a client to run as the background service from
	// now on: install and start it, then hand over.
	CommandService = "service"
	// CommandUpdate tells a client to install the release its relay offers
	// now, whatever its update policy says, unless updates are off (D29).
	CommandUpdate = "update"
)

// Command is what GET /relay/commands delivers.
type Command struct {
	ID   string    `json:"id"`
	Kind string    `json:"kind"`
	At   time.Time `json:"at"`
}

// Plans a client answers a CommandService with.
const (
	PlanNoPrompt    = "no_prompt"    // it installs at once, without asking anyone
	PlanAdminPrompt = "admin_prompt" // Windows asks for an administrator on that machine's screen
	PlanRefused     = "refused"      // it cannot, and Detail says why
)

// Plans a client answers a CommandUpdate with (and PlanRefused).
const (
	PlanUpdating = "updating"   // it installs the offered release now
	PlanUpToDate = "up_to_date" // it runs the offered release already
	PlanLater    = "later"      // it cannot now (a terminal view is open); the request stays queued
)

// CommandAck is a client's immediate answer to a Command: its plan.
type CommandAck struct {
	Plan   string `json:"plan"`
	Detail string `json:"detail,omitempty"`
}

// ---------------------------------------------------------------------------
// Console views

// WatchedRepo is one entry of a client's watch list, with what it last
// fetched.
type WatchedRepo struct {
	Repo          string     `json:"repo"`
	AddedAt       time.Time  `json:"added_at"`
	LastTag       string     `json:"last_tag,omitempty"`
	LastFetchedAt *time.Time `json:"last_fetched_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
}

// PromoteResult is the answer to POST /admin/clients/:id/promote: the
// client's plan, or why the relay or the client refused.
type PromoteResult struct {
	Plan   string    `json:"plan"` // a Plan*; "" when the client did not answer in time
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
}

// UpdateResult is the answer to POST /admin/clients/:id/update, and the
// last such request kept on the client's presence (D29).
type UpdateResult struct {
	// Plan is the client's answer, a Plan*; "" while Queued, or when a
	// connected client did not answer in time.
	Plan   string `json:"plan"`
	Detail string `json:"detail,omitempty"`
	// Version is the release the relay offered when it was asked.
	Version string `json:"version,omitempty"`
	// Queued: the client was not connected (or answered PlanLater); it gets
	// the request at its next check-in.
	Queued bool      `json:"queued"`
	At     time.Time `json:"at"`
}

// UpdateAllRow is one client's line in POST /admin/clients/update's reply:
// its result, or why it was not asked (Skipped).
type UpdateAllRow struct {
	ClientID string        `json:"client_id"`
	Label    string        `json:"label"`
	Skipped  string        `json:"skipped,omitempty"`
	Result   *UpdateResult `json:"result,omitempty"`
}

// ClientPresence is GET /admin/clients/:id/presence: where a client runs,
// how, whether it is connected now, and its watch list.
type ClientPresence struct {
	ClientID string `json:"client_id"`
	// Report is the last check-in's report; nil when it never checked in.
	Report *ClientReport `json:"report,omitempty"`
	// ReportedAt is when the report last changed.
	ReportedAt  *time.Time `json:"reported_at,omitempty"`
	FirstSeenAt *time.Time `json:"first_seen_at,omitempty"`
	LastSeenAt  *time.Time `json:"last_checkin_at,omitempty"`
	PeerIP      string     `json:"peer_ip,omitempty"`
	// Connected: the client holds the live channel now (a service, or a
	// --tui that is open).
	Connected bool `json:"connected"`
	// PromoteBlocked says why "Run as a service" cannot be asked now; ""
	// when it can.
	PromoteBlocked string         `json:"promote_blocked,omitempty"`
	LastPromote    *PromoteResult `json:"last_promote,omitempty"`
	// UpdateOffered is the release the relay offers this client's platform
	// now ("" when none); UpdateBlocked says why "Update now" cannot be
	// asked ("" when it can); LastUpdate is the last such request, with
	// Queued set while it waits for the client (D29).
	UpdateOffered string        `json:"update_offered,omitempty"`
	UpdateBlocked string        `json:"update_blocked,omitempty"`
	LastUpdate    *UpdateResult `json:"last_update,omitempty"`
	Watch         []WatchedRepo `json:"watch"`
	// r2-C: External says the last check-in came from outside the local
	// network (D28): a public peer address, or through [relay] proxy_addrs.
	External bool `json:"external"`
	// WANRefusedAt is the last time a request from outside was refused
	// because WAN access was off for this client (or for everyone).
	WANRefusedAt *time.Time `json:"wan_refused_at,omitempty"`
	// N3: Conn is the console's connection profile setting for it.
	Conn ConnSetting `json:"conn"`
}

// PresenceSummary is one row of GET /admin/presence, for the client list.
type PresenceSummary struct {
	ClientID  string `json:"client_id"`
	Connected bool   `json:"connected"`
	RunMode   string `json:"run_mode,omitempty"`
	Service   string `json:"service,omitempty"`
	// N3: the connection profile it uses now and the one it is set to
	// (by the console, or on the machine); Locked by the console.
	ConnInUse  string `json:"conn_in_use,omitempty"`
	ConnSet    string `json:"conn_set,omitempty"`
	ConnLocked bool   `json:"conn_locked,omitempty"`
}

// WatchRequest is PUT /admin/clients/:id/watch: the whole list.
type WatchRequest struct {
	Repos []string `json:"repos"`
}

// MaxWatched bounds a client's watch list.
const MaxWatched = 50

// ---------------------------------------------------------------------------
// Install scripts (D27)

// Code kinds.
const (
	CodeKindCode    = ""        // typed by a person (also listed as "code")
	CodeKindInstall = "install" // carried by an install script's URL
)

// Install script families.
const (
	InstallWindows = "windows"
	InstallUnix    = "unix"
)

// InstallPlatforms are the client builds an install script may fetch.
var InstallPlatforms = []string{"windows-amd64", "linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64"}

// InstallRequest is POST /admin/install.
type InstallRequest struct {
	OS      string `json:"os,omitempty"` // InstallWindows, InstallUnix, or "" for both
	Label   string `json:"label,omitempty"`
	Profile string `json:"profile"`
	Hours   int    `json:"hours,omitempty"` // 0 = the code_default_hours setting
	Service bool   `json:"service,omitempty"`
	// N4: the connection profile the new client is set to ("" = automatic,
	// left to the machine): the install line uses that profile's console
	// URL, and the setting is the console's from enrolment on.
	ConnProfile    string `json:"conn_profile,omitempty"`
	ConnNoFallback bool   `json:"conn_no_fallback,omitempty"`
	ConnLocked     bool   `json:"conn_locked,omitempty"`
}

// InstallReply is the answer: the code (its secret shown this once), the
// script's address and the one line that runs it.
type InstallReply struct {
	Code      Code   `json:"code"`
	ScriptURL string `json:"script_url"`
	// DownloadURL is the script as a file to save.
	DownloadURL string `json:"download_url"`
	OneLiner    string `json:"one_liner"`
	// WebFingerprint is set when the console's certificate is not publicly
	// trusted: the one line and the script accept only that certificate.
	WebFingerprint string `json:"web_fingerprint,omitempty"`
	// Lines are the one line for every family, Windows first, all for the
	// same code: whoever pastes it on the wrong system picks the other
	// (N0). The fields above are the requested family's, or Windows'.
	Lines []InstallLine `json:"lines"`
}

// InstallLine is one family's line and script.
type InstallLine struct {
	OS          string `json:"os"`
	ScriptURL   string `json:"script_url"`
	DownloadURL string `json:"download_url"`
	OneLiner    string `json:"one_liner"`
}

// r2-B: audit actions.
const (
	AuditCheckin   = "checkin"        // a client's report changed
	AuditWatch     = "watch_change"   // a client's watch list was set
	AuditPromote   = "client_promote" // "Run as a service" asked of a client
	AuditUpdateNow = "client_update"  // "Update now" asked of a client (D29)
	AuditInstall   = "install_create" // an install code and script were made
	AuditInstallU  = "install_use"    // an install script or client was fetched
)
