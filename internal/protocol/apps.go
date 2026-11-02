package protocol

import "time"

// The upgrade gateway: apps the relay
// serves updates for, the generic offer, and what an instance reports.

// AppMghagent is the relay's own client as an app. Every client enrolled
// before apps existed belongs to it, and so does every agent-style client.
const AppMghagent = "mghagent"

// AppProfilePrefix names an app instance's derived profile: "app:<slug>". It
// is not a stored profile — its rights are worked out from the app on every
// request (the app's repo only, its channel, download only) — and no profile
// a person creates can carry the name, since ':' is not allowed in one.
const AppProfilePrefix = "app:"

// App channels: what an app's instances are offered by default.
const (
	AppChannelPublished  = "published"
	AppChannelPrerelease = "prerelease" // pre-releases as well as published
)

// App promotion: whether a release is offered as soon as GitHub publishes it
// (automatic) or only once promoted in the console (manual).
const (
	PromotionAutomatic = "automatic"
	PromotionManual    = "manual"
)

// App audience: which network an app's instances are offered updates on.
const (
	AudienceBoth     = "both"
	AudienceInternal = "internal"
	AudienceExternal = "external"
)

// App enrolment policy. Phase 1 serves "code"; "approve" and "lan_auto" are
// accepted and stored, and take effect with approval enrolment (phase 2).
const (
	EnrolCode    = "code"
	EnrolApprove = "approve"
	EnrolLANAuto = "lan_auto"
)

// App is an application the relay serves updates for (GET /admin/apps).
type App struct {
	Slug          string    `json:"slug"`
	Name          string    `json:"name"`
	Repo          string    `json:"repo"`
	AssetPattern  string    `json:"asset_pattern"` // "" = the build standard's name-vX-os-arch.ext
	Channel       string    `json:"channel"`       // AppChannel*
	Promotion     string    `json:"promotion"`     // Promotion*
	SigningKeyHex string    `json:"signing_key_hex"`
	Audience      string    `json:"audience"`      // Audience*
	EnrolPolicy   string    `json:"enrol_policy"`  // Enrol*
	UpdatePolicy  string    `json:"update_policy"` // "" = household default
	MaxPending    int       `json:"max_pending"`
	TicketHours   int       `json:"ticket_hours"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
	CreatedBy     string    `json:"created_by,omitempty"`

	// Console only, filled in on the admin routes.
	Instances  int    `json:"instances"`   // live (not revoked) instances
	Behind     int    `json:"behind"`      // instances not on the offered release
	Pending    int    `json:"pending"`     // tickets waiting for approval (phase 2)
	LatestTag  string `json:"latest_tag"`  // newest release on the app's channel
	OfferedTag string `json:"offered_tag"` // what an up-to-date check is offered now; "" = held
}

// AppInput is POST /admin/apps and PUT /admin/apps/:slug. A nil field is
// left as it is on PUT; slug and repo are fixed once created.
type AppInput struct {
	Slug          *string `json:"slug,omitempty"`
	Name          *string `json:"name,omitempty"`
	Repo          *string `json:"repo,omitempty"`
	AssetPattern  *string `json:"asset_pattern,omitempty"`
	Channel       *string `json:"channel,omitempty"`
	Promotion     *string `json:"promotion,omitempty"`
	SigningKeyHex *string `json:"signing_key_hex,omitempty"`
	Audience      *string `json:"audience,omitempty"`
	EnrolPolicy   *string `json:"enrol_policy,omitempty"`
	UpdatePolicy  *string `json:"update_policy,omitempty"`
	MaxPending    *int    `json:"max_pending,omitempty"`
	TicketHours   *int    `json:"ticket_hours,omitempty"`
	Enabled       *bool   `json:"enabled,omitempty"`
}

// AppRepoCheck is POST /admin/apps/check-repo: whether the relay can see a
// repository, for the Add app form's live check.
type AppRepoCheck struct {
	Repo     string `json:"repo"`
	Visible  bool   `json:"visible"`
	Releases int    `json:"releases"`
	Detail   string `json:"detail,omitempty"`
	// TakenBy is the slug of an app already serving this repository.
	TakenBy string `json:"taken_by,omitempty"`
}

// AppRelease is one release as an app's Releases tab lists it.
type AppRelease struct {
	Release
	Promoted   bool       `json:"promoted"`
	PromotedAt *time.Time `json:"promoted_at,omitempty"`
	PromotedBy string     `json:"promoted_by,omitempty"`
	Offered    bool       `json:"offered"`    // what a check is offered now
	Running    int        `json:"running"`    // instances reporting this version
	OfferedTo  int        `json:"offered_to"` // instances behind it that would be offered it
}

// Offer is the single answer to "is there anything for me?":
// GET /relay/apps/:app/update, and InstanceReply.Offer.
type Offer struct {
	App         string     `json:"app"`
	Version     string     `json:"version"`
	Channel     string     `json:"channel"`
	Policy      string     `json:"policy"` // off | notify | automatic, resolved
	Platform    string     `json:"platform"`
	AssetID     int64      `json:"asset_id"`
	Name        string     `json:"name"`
	Size        int64      `json:"size"`
	SHA256      string     `json:"sha256"`
	Signature   string     `json:"signature,omitempty"` // base64 Ed25519, passed through
	Notes       string     `json:"notes,omitempty"`     // reserved (phase 3): the release body
	PublishedAt *time.Time `json:"published_at,omitempty"`
}

// InstanceReport is POST /relay/apps/:app/report: what an instance runs.
type InstanceReport struct {
	Version     string `json:"version"`
	Platform    string `json:"platform"`               // goos-arch
	UpdateState string `json:"update_state,omitempty"` // staged | swapped | confirmed | rolled_back | failed
	Detail      string `json:"detail,omitempty"`
}

// InstanceReply answers a report: when to check again and, so a client
// needs one call per cycle, the offer.
type InstanceReply struct {
	Every int            `json:"every"` // seconds until the next check
	Offer *Offer         `json:"offer,omitempty"`
	Relay *RelayEndpoint `json:"relay,omitempty"`
}

// Instance states (protocol.Client.State), derived.
const (
	InstanceActive  = "active"
	InstanceHeld    = "held"
	InstanceRevoked = "revoked"
)

// Audit actions for apps. update_offered and client_change carry the app.
const (
	AuditAppCreated           = "app_created"
	AuditAppUpdated           = "app_updated"
	AuditAppDeleted           = "app_deleted"
	AuditAppReleasePromoted   = "app_release_promoted"
	AuditAppReleaseUnpromoted = "app_release_unpromoted"
	AuditInstanceHeld         = "instance_held"
	AuditInstanceReleased     = "instance_released"
	AuditOfferNoAsset         = "offer_no_asset"
	AuditOfferUnsigned        = "offer_unsigned"
)

// Token scopes for apps (in AllScopes).
const (
	ScopeAppsRead  = "apps:read"
	ScopeAppsWrite = "apps:write"
)

// Live-stream event types for apps (Event.Type).
const (
	EventApp              = "app"
	EventInstanceReported = "instance_reported"
	EventReleasePromoted  = "release_promoted"
)

// InstanceCheckEvery is how often, in seconds, an instance checks for an
// update unless a reply says otherwise.
const InstanceCheckEvery = 300

// ------------------------------------------------- phase 2: approval enrolment

// PathEnrollTicket is GET <PathEnrollTicket><token>: an instance polling the
// enrolment it asked for without a code (UG-4).
const PathEnrollTicket = APIPrefix + "/enroll/ticket/"

// AppPath is an app route on the [relay] listener:
// /relay/apps/<app><rest>, rest being "/update", "/releases", "/report" or
// "/assets/<id>".
func AppPath(app, rest string) string { return RelayPrefix + "/apps/" + app + rest }

// Ticket states. A client is only ever told pending, approved or denied:
// expired reads as denied (UG-12), and collected is 410.
const (
	TicketPending   = "pending"
	TicketApproved  = "approved"
	TicketDenied    = "denied"
	TicketExpired   = "expired"
	TicketCollected = "collected"
)

// TicketPollEvery is how often, in seconds, an instance polls its ticket
// unless the relay says otherwise ([enroll] ticket_poll_seconds).
const TicketPollEvery = 30

// EnrollTicket is the reply to POST /enroll without a code (202) and to
// GET /enroll/ticket/:token. Ticket, the poll token, is in the first reply
// only; Enrolled is in the one reply after approval, after which the ticket
// is collected and answers 410.
type EnrollTicket struct {
	Ticket    string          `json:"ticket,omitempty"`
	State     string          `json:"state"` // pending | approved | denied
	PollEvery int             `json:"poll_every"`
	ExpiresAt time.Time       `json:"expires_at"`
	Enrolled  *EnrollResponse `json:"enrolled,omitempty"`
}

// Ticket is a pending (or decided) enrolment as the console's Approvals
// list shows it (GET /admin/enroll/tickets).
type Ticket struct {
	ID        string     `json:"id"`
	App       string     `json:"app"`
	AppName   string     `json:"app_name,omitempty"`
	Hostname  string     `json:"hostname"`
	OS        string     `json:"os"`
	Arch      string     `json:"arch"`
	Version   string     `json:"version"`
	From      string     `json:"from"`
	Network   string     `json:"network"` // lan | wan, judged as [enroll] outside judges it
	State     string     `json:"state"`   // Ticket*
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	DecidedAt *time.Time `json:"decided_at,omitempty"`
	DecidedBy string     `json:"decided_by,omitempty"`
	ClientID  string     `json:"client_id,omitempty"`
	// Pairing names the request's key (e.g. "K3QZ-7MDA"); the instance
	// shows the same code while it waits. Approve only when they match.
	Pairing string `json:"pairing"`
}

// TicketApproval is POST /admin/enroll/tickets/:id/approve. Every field is
// optional: the label defaults to the hostname, the channel to the app's,
// Allow WAN to off.
type TicketApproval struct {
	Label    string `json:"label,omitempty"`
	Channel  string `json:"channel,omitempty"`
	AllowWAN bool   `json:"allow_wan,omitempty"`
}

// Ticket networks.
const (
	NetworkLAN = "lan"
	NetworkWAN = "wan"
)

// Audit actions for approval enrolment.
const (
	AuditInstanceRequested     = "instance_requested"
	AuditInstanceApproved      = "instance_approved"
	AuditInstanceAutoApproved  = "instance_auto_approved"
	AuditInstanceDenied        = "instance_denied"
	AuditInstanceTicketExpired = "instance_ticket_expired"
)

// ScopeEnrollApprove lets a token list, approve and deny tickets.
const ScopeEnrollApprove = "enroll:approve"

// Live-stream events for tickets. Their text never names the host: members
// read the stream too.
const (
	EventTicketCreated = "ticket_created"
	EventTicketDecided = "ticket_decided"
)

// EnrolInfo is GET /admin/enrol-info: what the console's Enrol tab shows a
// person setting up an instance.
type EnrolInfo struct {
	// WebFingerprint is the SHA-256 of the web listener's certificate, hex;
	// "" behind a TLS proxy.
	WebFingerprint string     `json:"web_fingerprint"`
	WebNotAfter    *time.Time `json:"web_not_after,omitempty"`
}
