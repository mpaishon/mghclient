package protocol

import (
	"cmp"
	"time"
)

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

// App update models: who talks to the relay for an app. Read-only on the
// wire, derived from the record (see App.UpdateModel); never stored.
const (
	UpdateModelStandalone  = "standalone"   // every install enrols here and updates itself (house standard Profile B)
	UpdateModelHub         = "hub"          // hub-and-spoke: only the app's hubs enrol here (Profile A, DistributionOnly)
	UpdateModelRelayClient = "relay_client" // mghagent: the relay is the hub for its own client
)

// DeriveUpdateModel is the rule: the relay's own client is a relay client
// (it can never be distribution-only), a distribution-only app is
// hub-and-spoke, and anything else is standalone.
func DeriveUpdateModel(slug string, distributionOnly bool) string {
	switch {
	case slug == AppMghagent:
		return UpdateModelRelayClient
	case distributionOnly:
		return UpdateModelHub
	default:
		return UpdateModelStandalone
	}
}

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
	// DistributionOnly is a hub-and-spoke app (house standard Profile A,
	// A-08): only the instances labelled as one of Hubs may enrol, on every
	// path, and at most one live instance per hub label. Hubs empty with
	// DistributionOnly on is "enrol none".
	DistributionOnly bool     `json:"distribution_only"`
	Hubs             []string `json:"hubs"`
	// Signed and HubCount are derived from SigningKeyHex and Hubs, so the
	// console can say "signed" and "1 of 2 hubs" without either; they are
	// all a member's view (AppMemberView) carries of them.
	Signed   bool `json:"signed"`
	HubCount int  `json:"hub_count"`
	// UpdateModel is UpdateModel*, derived on every read: the relay's own
	// client (AppMghagent) is a relay client, a DistributionOnly app is
	// hub-and-spoke, anything else standalone. Read-only: AppInput has no
	// such field, so a request that sends it has it ignored.
	UpdateModel string `json:"update_model"`

	// Console only, filled in on the admin routes.
	Instances int `json:"instances"` // live (not revoked) instances
	Behind    int `json:"behind"`    // instances not on the offered release
	// Redeploy is the part of Behind that reports only (InstallModeReport):
	// behind, and upgraded by redeploying rather than by an update.
	Redeploy   int    `json:"redeploy"`
	Pending    int    `json:"pending"`     // tickets waiting for approval (phase 2)
	LatestTag  string `json:"latest_tag"`  // newest release on the app's channel
	OfferedTag string `json:"offered_tag"` // what an up-to-date check is offered now; "" = held
	// AwaitingPromotion counts the releases waiting for the admin to promote
	// them (apps.Awaiting): always 0 for automatic promotion or a disabled
	// app. AwaitingTag and AwaitingPublishedAt are the newest of them.
	AwaitingPromotion   int        `json:"awaiting_promotion"`
	AwaitingTag         string     `json:"awaiting_tag"`
	AwaitingPublishedAt *time.Time `json:"awaiting_published_at"` // null when nothing waits
	// Violations counts live instances a distribution-only app would not
	// enrol today (each one's Client.DistributionViolation says why).
	Violations int `json:"violations"`
}

// AppMemberView is an app as a member's session sees it on GET /apps and
// GET /apps/:slug: what the Apps list and the app's Releases tab show, and
// nothing of how the app is administered. It is an allow-list, so a field
// added to App stays admin-only until it is added here as well.
//
// Left out (admin only): signing_key_hex (Signed says whether there is
// one), hubs (hub instance labels; HubCount says how many), audience,
// enrol_policy, update_policy, max_pending, ticket_hours, asset_pattern and
// created_by.
type AppMemberView struct {
	Slug             string    `json:"slug"`
	Name             string    `json:"name"`
	Repo             string    `json:"repo"`
	Channel          string    `json:"channel"`
	Promotion        string    `json:"promotion"`
	Enabled          bool      `json:"enabled"`
	CreatedAt        time.Time `json:"created_at"`
	DistributionOnly bool      `json:"distribution_only"`
	Signed           bool      `json:"signed"`
	HubCount         int       `json:"hub_count"`
	UpdateModel      string    `json:"update_model"`

	Instances  int    `json:"instances"`
	Behind     int    `json:"behind"`
	Redeploy   int    `json:"redeploy"`
	Pending    int    `json:"pending"`
	LatestTag  string `json:"latest_tag"`
	OfferedTag string `json:"offered_tag"`
	Violations int    `json:"violations"`

	AwaitingPromotion   int        `json:"awaiting_promotion"`
	AwaitingTag         string     `json:"awaiting_tag"`
	AwaitingPublishedAt *time.Time `json:"awaiting_published_at"` // null when nothing waits
}

// MemberView is a as AppMemberView. Signed, HubCount and UpdateModel are
// worked out from a's own key, hubs and flag too, so an App not built by
// apps.FromRow is safe.
func (a App) MemberView() AppMemberView {
	return AppMemberView{
		Slug: a.Slug, Name: a.Name, Repo: a.Repo, Channel: a.Channel, Promotion: a.Promotion,
		Enabled: a.Enabled, CreatedAt: a.CreatedAt, DistributionOnly: a.DistributionOnly,
		Signed: a.Signed || a.SigningKeyHex != "", HubCount: max(a.HubCount, len(a.Hubs)),
		UpdateModel: cmp.Or(a.UpdateModel, DeriveUpdateModel(a.Slug, a.DistributionOnly)),
		Instances:   a.Instances, Behind: a.Behind, Redeploy: a.Redeploy, Pending: a.Pending,
		LatestTag: a.LatestTag, OfferedTag: a.OfferedTag, Violations: a.Violations,
		AwaitingPromotion: a.AwaitingPromotion, AwaitingTag: a.AwaitingTag, AwaitingPublishedAt: a.AwaitingPublishedAt,
	}
}

// AppInput is POST /admin/apps and PUT /admin/apps/:slug. A nil field is
// left as it is on PUT; slug and repo are fixed once created. App's
// read-only fields (update_model and the console figures) are not here, so
// a body that carries them has them ignored.
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
	// DistributionOnly and Hubs: see App. Hubs replaces the whole list.
	DistributionOnly *bool     `json:"distribution_only,omitempty"`
	Hubs             *[]string `json:"hubs,omitempty"`
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
	// InstallMode is how this install is kept current: InstallModeSelf
	// (it takes the offer and swaps its own binary) or InstallModeReport (a
	// container: it reports its version and is upgraded by redeploying).
	// Empty is self, so an SDK that predates the field reads as before; a
	// relay that predates it ignores it. Any other value is refused (400).
	// Only a standalone app's instance can report only: from a hub or a
	// relay client the value is ignored.
	InstallMode string `json:"install_mode,omitempty"`
}

// Install modes (InstanceReport.InstallMode, Client.InstallMode).
const (
	InstallModeSelf   = "self"   // self-updating: takes the offer and installs it
	InstallModeReport = "report" // reports only: shown as behind, redeployed, never installs
)

// ValidInstallMode reports whether m is an install mode a report may carry:
// empty (self), self or report.
func ValidInstallMode(m string) bool {
	return m == "" || m == InstallModeSelf || m == InstallModeReport
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
	// AuditInstanceModeChanged is an instance's reports switching between
	// self-updating and reports only, with the update state it showed.
	AuditInstanceModeChanged = "instance_mode_changed"
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
// the update policy to the app's (off | notify | automatic set it on the
// instance in the same step), Allow WAN to off.
type TicketApproval struct {
	Label        string `json:"label,omitempty"`
	Channel      string `json:"channel,omitempty"`
	UpdatePolicy string `json:"update_policy,omitempty"`
	AllowWAN     bool   `json:"allow_wan,omitempty"`
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
