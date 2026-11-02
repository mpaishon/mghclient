// Package protocol holds the wire types shared by the relay server (mghRelay)
// and its client (mghagent). It has no server-only dependencies, so the client
// imports it without pulling in Gin, GORM or the PKI.
//
// JSON keys are snake_case. Times are RFC 3339 in UTC. Errors are
// {"error": "..."} with an HTTP status that says what went wrong.
package protocol

import "time"

// Path prefixes. The web console and its API share [web]; the client API is
// the separate mutual-TLS [relay] listener.
const (
	UIPrefix    = "/ui"
	APIPrefix   = UIPrefix + "/api"
	RelayPrefix = "/relay"

	PathHealth  = APIPrefix + "/health"
	PathEnroll  = APIPrefix + "/enroll"
	PathWebhook = APIPrefix + "/hooks/github"
	PathLink    = APIPrefix + "/l/" // + token

	PathWhoAmI       = RelayPrefix + "/whoami"
	PathRepos        = RelayPrefix + "/repos"
	PathAssets       = RelayPrefix + "/assets/" // + asset id
	PathRenew        = RelayPrefix + "/renew"
	PathUpdate       = RelayPrefix + "/update"
	PathUpdateBinary = RelayPrefix + "/update/binary"
)

// Headers.
const (
	// HeaderContentSHA256 carries the hex sha256 of a download's whole body.
	// The client verifies it before extracting anything.
	HeaderContentSHA256 = "X-Content-SHA256"
	// HeaderCache says whether a download was served from the relay's cache:
	// "hit" or "miss".
	HeaderCache = "X-Relay-Cache"
)

// Error is every non-2xx JSON body.
type Error struct {
	Error string `json:"error"`
}

// ---------------------------------------------------------------------------
// Access control

// Channel is the kind of release a profile may see.
type Channel string

const (
	ChannelPublished  Channel = "published"
	ChannelPrerelease Channel = "prerelease"
	ChannelDraft      Channel = "draft"
)

// ChannelOf names a release's channel from GitHub's two flags.
func ChannelOf(draft, prerelease bool) Channel {
	switch {
	case draft:
		return ChannelDraft
	case prerelease:
		return ChannelPrerelease
	default:
		return ChannelPublished
	}
}

// Action is what a principal is trying to do with a repository.
type Action string

const (
	ActionList     Action = "list"     // see the repo and its releases in the catalog
	ActionDownload Action = "download" // download a release asset
	ActionContent  Action = "content"  // read repository files (profile.content)
	ActionImages   Action = "images"   // list container images (profile.images)
	ActionManage   Action = "manage"   // delete releases / images (profile.manage)
	ActionLink     Action = "link"     // make a share link (profile.links)
)

// Built-in profile names. They cannot be deleted; their rules can be edited.
const (
	ProfileOwner    = "owner"
	ProfileInternal = "internal"
	ProfileExternal = "external"
	ProfileMember   = "member" // what a console user with role member may do
)

// Profile is an access profile. A client gets one when its enrolment code is
// made; a member console user is governed by ProfileMember.
type Profile struct {
	Name     string    `json:"name"`
	Builtin  bool      `json:"builtin"`
	Repos    []string  `json:"repos"`    // "owner/*", "owner/name", or "*"
	Channels []Channel `json:"channels"` // which releases are visible
	Content  bool      `json:"content"`
	Images   bool      `json:"images"`
	Manage   bool      `json:"manage"`
	Links    bool      `json:"links"`
}

// Role is a console user's role.
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

// ---------------------------------------------------------------------------
// Catalog

// Repo is one repository the relay knows about.
type Repo struct {
	Owner         string    `json:"owner"`
	Name          string    `json:"name"`
	FullName      string    `json:"full_name"`
	Private       bool      `json:"private"`
	Archived      bool      `json:"archived"`
	Description   string    `json:"description,omitempty"`
	DefaultBranch string    `json:"default_branch"`
	PushedAt      time.Time `json:"pushed_at"`
	ImageName     string    `json:"image_name,omitempty"` // from the repo's bld, or the house default
	// NoImage says the repo's bld declares imageName empty: it publishes none.
	NoImage bool `json:"no_image,omitempty"`
	// LatestTag is the newest published release visible to the caller, if any.
	LatestTag       string     `json:"latest_tag,omitempty"`
	LatestPublished *time.Time `json:"latest_published_at,omitempty"`
	HookState       string     `json:"hook_state,omitempty"` // admin views only: HookState*
	SyncedAt        time.Time  `json:"synced_at"`            // last time the relay read it from GitHub
}

// Release is one GitHub release.
type Release struct {
	ID          int64      `json:"id"`
	Repo        string     `json:"repo"` // full name
	Tag         string     `json:"tag"`
	Name        string     `json:"name"`
	Channel     Channel    `json:"channel"`
	CreatedAt   time.Time  `json:"created_at"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
	Assets      []Asset    `json:"assets"`
	// Image says where a container image for this tag exists: "", "registry".
	Image  string `json:"image,omitempty"`
	Pinned bool   `json:"pinned"`
}

// Asset is one release asset. ID is GitHub's asset id, which is also the
// relay's download key.
type Asset struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"` // from GitHub's digest, or recorded at first fill
	// Platform is goos-arch when the name follows the build standard.
	Platform string `json:"platform,omitempty"`
	Cached   bool   `json:"cached"`
}

// Image is one container image tag on GHCR.
type Image struct {
	Repo      string    `json:"repo"`
	Name      string    `json:"name"` // ghcr.io/owner/name
	Tag       string    `json:"tag"`
	VersionID int64     `json:"version_id"`
	CreatedAt time.Time `json:"created_at"`
	// Release is the tag of the release it belongs to, empty when none exists.
	Release string `json:"release,omitempty"`
}

// ContentEntry is one entry in a repository directory listing or tree.
type ContentEntry struct {
	Path string `json:"path"`
	Name string `json:"name"`
	Type string `json:"type"` // file, dir, symlink, submodule
	Size int64  `json:"size"`
	SHA  string `json:"sha"`
}

// ---------------------------------------------------------------------------
// Enrolment and identity

// EnrollRequest is POSTed to PathEnroll on the web listener with a one-time
// code. The client generated the key; only the CSR leaves the machine.
type EnrollRequest struct {
	// App is the app the client enrols as. Empty
	// is taken from the code, so an older mghagent still enrols.
	App      string `json:"app,omitempty"`
	Code     string `json:"code"`
	CSRPEM   string `json:"csr_pem"`
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	Arch     string `json:"arch,omitempty"`
	Version  string `json:"version,omitempty"`
}

// RelayEndpoint is where the mutual-TLS client API is.
type RelayEndpoint struct {
	Port  string   `json:"port"`
	Names []string `json:"names"` // the [relay] san names its certificate covers
	// The relay's internal and public host:port. Internal is the
	// relay_internal_addr setting, or one derived from [relay] san and
	// listen; Public is relay_public_addr, empty when there is none. Sent at
	// enrolment and in every check-in reply, so clients learn a change.
	Internal string `json:"internal,omitempty"`
	Public   string `json:"public,omitempty"`
	// Profiles are the household's connection profiles, in order, each
	// RelayAddr as host:port and without Networks. Internal and Public stay
	// for clients that predate profiles: the first internal and the first
	// external profile.
	Profiles []ConnectionProfile `json:"profiles,omitempty"`
}

// EnrollResponse carries the signed certificate and the CA to trust.
type EnrollResponse struct {
	ClientID      string        `json:"client_id"`
	Profile       string        `json:"profile"`
	CertPEM       string        `json:"cert_pem"`
	CAPEM         string        `json:"ca_pem"`
	CAFingerprint string        `json:"ca_fingerprint"` // sha256 of the CA certificate DER, hex
	NotAfter      time.Time     `json:"not_after"`
	Relay         RelayEndpoint `json:"relay"`
	// Conn is the console's connection profile setting, when the
	// install line chose one.
	Conn *ConnSetting `json:"conn,omitempty"`
}

// WhoAmI is the reply of PathWhoAmI.
type WhoAmI struct {
	ClientID   string    `json:"client_id"`
	Label      string    `json:"label"`
	Profile    Profile   `json:"profile"`
	NotAfter   time.Time `json:"not_after"`
	RenewAfter time.Time `json:"renew_after"` // when the client should renew
	Server     string    `json:"server_version"`
	Update     *Update   `json:"update,omitempty"`
	// The upgrade gateway: the client's app, resolved channel, hold and
	// state (protocol.Client's).
	App     string `json:"app,omitempty"`
	Channel string `json:"channel,omitempty"`
	Hold    bool   `json:"hold"`
	State   string `json:"state,omitempty"`
}

// RenewRequest is POSTed to PathRenew over mutual TLS with a CSR for a new key.
type RenewRequest struct {
	CSRPEM string `json:"csr_pem"`
}

// RenewResponse carries the new certificate.
type RenewResponse struct {
	CertPEM  string    `json:"cert_pem"`
	NotAfter time.Time `json:"not_after"`
}

// ---------------------------------------------------------------------------
// Client update

// Update policies.
const (
	UpdateOff       = "off"
	UpdateNotify    = "notify"
	UpdateAutomatic = "automatic"
)

// Update is what the relay offers a client: the newest published mghagent
// release. The signature is checked by the client against its own
// compiled-in keys; the relay is not trusted for it.
type Update struct {
	Version   string `json:"version"`
	Policy    string `json:"policy"`
	Platform  string `json:"platform,omitempty"`
	Name      string `json:"name,omitempty"`
	Size      int64  `json:"size,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	Signature string `json:"signature,omitempty"` // base64 Ed25519 over the release message
}

// Update states a client reports in its user agent / whoami query.
const (
	UpdateStaged     = "staged"
	UpdateSwapped    = "swapped"
	UpdateConfirmed  = "confirmed"
	UpdateRolledBack = "rolled_back"
	UpdateFailed     = "failed"
)

// ---------------------------------------------------------------------------
// Admin views

// Client is an enrolled client as the console shows it.
type Client struct {
	ID           string     `json:"id"`
	Label        string     `json:"label"`
	Profile      string     `json:"profile"`
	Hostname     string     `json:"hostname,omitempty"`
	OS           string     `json:"os,omitempty"`
	Arch         string     `json:"arch,omitempty"`
	Version      string     `json:"version,omitempty"`
	UpdatePolicy string     `json:"update_policy,omitempty"` // empty = household default
	UpdateState  string     `json:"update_state,omitempty"`
	EnrolledAt   time.Time  `json:"enrolled_at"`
	NotAfter     time.Time  `json:"not_after"`
	LastSeenAt   *time.Time `json:"last_seen_at,omitempty"`
	LastSeenFrom string     `json:"last_seen_from,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	ForceRenew   bool       `json:"force_renew"`
	// AllowWAN lets this client in from outside the local network
	// while the household's "Allow clients from outside" is on. Off by
	// default.
	AllowWAN bool `json:"allow_wan"`
	// The upgrade gateway: the app this client is an instance of, its
	// channel override ("" = the app's), whether it is held (offered
	// nothing), and its state (InstanceActive, InstanceHeld,
	// InstanceRevoked), derived.
	App     string `json:"app"`
	Channel string `json:"channel,omitempty"`
	Hold    bool   `json:"hold"`
	State   string `json:"state"`
}

// Code is an enrolment code as listed (the code itself is shown once).
type Code struct {
	ID        string     `json:"id"`
	Label     string     `json:"label"`
	Profile   string     `json:"profile"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	ClientID  string     `json:"client_id,omitempty"`
	Code      string     `json:"code,omitempty"` // only in the create reply
	// Kind is CodeKindCode ("") for a code typed by a person, or
	// CodeKindInstall for an install script's. Either enrols.
	Kind string `json:"kind,omitempty"`
	// The connection profile an install code sets its client to.
	ConnProfile    string `json:"conn_profile,omitempty"`
	ConnNoFallback bool   `json:"conn_no_fallback,omitempty"`
	ConnLocked     bool   `json:"conn_locked,omitempty"`
	// App is the app the code enrols an instance of.
	App string `json:"app"`
}

// User is a console user.
type User struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	Role        Role       `json:"role"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	Disabled    bool       `json:"disabled"`
}

// APIToken scopes. A console session holds every scope.
const (
	ScopeStatusRead   = "status:read"
	ScopeCatalogRead  = "catalog:read"
	ScopeCacheWrite   = "cache:write"
	ScopeRetentionRun = "retention:run"
	ScopeClientsRead  = "clients:read"
	ScopeWebhooks     = "webhooks:write"
)

// AllScopes is every scope a token may hold.
var AllScopes = []string{ScopeStatusRead, ScopeCatalogRead, ScopeCacheWrite, ScopeRetentionRun, ScopeClientsRead, ScopeWebhooks,
	ScopeAppsRead, ScopeAppsWrite, ScopeEnrollApprove} // the apps scopes

// TokenPrefix starts every API token, so a leaked one is recognisable.
const TokenPrefix = "mghr_"

// APIToken is an API token as listed (the secret is shown once).
type APIToken struct {
	ID           string     `json:"id"`
	Label        string     `json:"label"`
	Scopes       []string   `json:"scopes"`
	CreatedBy    string     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	LastUsedFrom string     `json:"last_used_from,omitempty"`
	Token        string     `json:"token,omitempty"` // only in the create reply
}

// ShareLink is an expiring download link for one asset.
type ShareLink struct {
	ID        string     `json:"id"`
	AssetID   int64      `json:"asset_id"`
	Repo      string     `json:"repo"`
	Tag       string     `json:"tag"`
	AssetName string     `json:"asset_name"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	MaxUses   int        `json:"max_uses"` // 0 = unlimited until expiry
	Uses      int        `json:"uses"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	URL       string     `json:"url,omitempty"` // only in the create reply
}

// CacheEntry is one cached blob.
type CacheEntry struct {
	SHA256       string    `json:"sha256"`
	Size         int64     `json:"size"`
	AssetIDs     []int64   `json:"asset_ids"`
	Names        []string  `json:"names"` // "owner/repo@tag/asset"
	FilledAt     time.Time `json:"filled_at"`
	LastAccessAt time.Time `json:"last_access_at"`
	Hits         int64     `json:"hits"`
	Pinned       bool      `json:"pinned"`
}

// CacheStats summarises the cache.
type CacheStats struct {
	UsedBytes    int64   `json:"used_bytes"`
	MaxBytes     int64   `json:"max_bytes"`
	MinFreeBytes int64   `json:"min_free_bytes"`
	FreeBytes    int64   `json:"free_bytes"` // on the volume
	PinnedBytes  int64   `json:"pinned_bytes"`
	Entries      int     `json:"entries"`
	Hits         int64   `json:"hits"`
	Misses       int64   `json:"misses"`
	HitRate      float64 `json:"hit_rate"`
	Evictions    int64   `json:"evictions"`
}

// Pin keeps a release's assets (or a repo's newest published release) out of
// eviction.
type Pin struct {
	ID        string    `json:"id"`
	Repo      string    `json:"repo"`
	Tag       string    `json:"tag,omitempty"` // empty = "latest published"
	CreatedAt time.Time `json:"created_at"`
}

// Reclaim kinds.
const (
	ReclaimOldRelease   = "old_release"   // beyond the newest K and older than N days
	ReclaimOldDraft     = "old_draft"     // a draft older than N days
	ReclaimOrphanImage  = "orphan_image"  // an image tag whose release is gone
	ReclaimUntagged     = "untagged"      // an untagged GHCR version
	ReclaimCacheBlob    = "cache_blob"    // a cached blob not used in N days
	ReclaimDeletedAsset = "deleted_asset" // a cached blob whose asset no longer exists
)

// ReclaimItem is one thing that could be deleted.
type ReclaimItem struct {
	Kind      string    `json:"kind"`
	Repo      string    `json:"repo"`
	Tag       string    `json:"tag,omitempty"`
	ReleaseID int64     `json:"release_id,omitempty"`
	VersionID int64     `json:"version_id,omitempty"`
	SHA256    string    `json:"sha256,omitempty"`
	Bytes     int64     `json:"bytes"`
	Age       string    `json:"age"` // human, e.g. "94d"
	CreatedAt time.Time `json:"created_at"`
	Reason    string    `json:"reason"`
}

// RetentionPolicy is the household retention policy.
type RetentionPolicy struct {
	KeepNewest  int `json:"keep_newest"`  // per repo, drafts included (MyGHAgent's purge rule)
	ReleaseDays int `json:"release_days"` // releases older than this beyond KeepNewest are reclaimable
	DraftDays   int `json:"draft_days"`   // drafts older than this are reclaimable
	CacheIdle   int `json:"cache_idle_days"`
}

// ReclaimReport is GET /admin/retention.
type ReclaimReport struct {
	Policy     RetentionPolicy `json:"policy"`
	Items      []ReclaimItem   `json:"items"`
	TotalBytes int64           `json:"total_bytes"`
	At         time.Time       `json:"at"`
}

// PurgeRequest asks for items to be deleted. DryRun defaults to true: a
// request has to say dry_run false to change anything.
type PurgeRequest struct {
	Items  []ReclaimItem `json:"items"`
	DryRun *bool         `json:"dry_run,omitempty"`
}

// StepResult is one step of a deletion, reported whatever its outcome — the
// same report MyGHAgent's TUI shows.
type StepResult struct {
	Step    string `json:"step"` // "release", "tag", "image", "cache"
	Target  string `json:"target"`
	Outcome string `json:"outcome"` // done, nothing_to_do, skipped, failed, would_do
	Detail  string `json:"detail,omitempty"`
}

// PurgeResult is the reply to a purge.
type PurgeResult struct {
	DryRun bool         `json:"dry_run"`
	Steps  []StepResult `json:"steps"`
}

// Hook states.
const (
	HookOK      = "ok"
	HookMissing = "missing"
	HookBroken  = "broken" // exists but the URL, secret or events are wrong, or deliveries fail
	HookOrg     = "org"    // covered by an organisation hook
	HookUnknown = "unknown"
)

// WebhookState is one repo's (or org's) hook as GET /admin/webhooks shows it.
type WebhookState struct {
	Target       string     `json:"target"` // owner/repo, or org:<name>
	State        string     `json:"state"`
	HookID       int64      `json:"hook_id,omitempty"`
	LastDelivery *time.Time `json:"last_delivery_at,omitempty"`
	LastEvent    string     `json:"last_event,omitempty"`
	Detail       string     `json:"detail,omitempty"`
}

// AuditEvent is one audit record.
type AuditEvent struct {
	ID      int64     `json:"id"`
	At      time.Time `json:"at"`
	Actor   string    `json:"actor"`   // "user:<name>", "client:<id>", "token:<label>", "link:<id>", "github", "system"
	Action  string    `json:"action"`  // Audit* below
	Target  string    `json:"target"`  // what it acted on
	Outcome string    `json:"outcome"` // ok, denied, failed
	From    string    `json:"from"`    // client address
	Detail  string    `json:"detail,omitempty"`
	Bytes   int64     `json:"bytes,omitempty"`
}

// Audit actions.
const (
	AuditLogin         = "login"
	AuditLogout        = "logout"
	AuditPassword      = "password_change"
	AuditUser          = "user_change"
	AuditToken         = "token_change"
	AuditCode          = "code_create"
	AuditEnroll        = "enroll"
	AuditRenew         = "renew"
	AuditRevoke        = "revoke"
	AuditClient        = "client_change"
	AuditProfile       = "profile_change"
	AuditDownload      = "download"
	AuditContent       = "content"
	AuditLinkCreate    = "link_create"
	AuditLinkRevoke    = "link_revoke"
	AuditLinkUse       = "link_use"
	AuditPurge         = "purge"
	AuditDelete        = "delete"
	AuditCache         = "cache_change"
	AuditWebhook       = "webhook"
	AuditSettings      = "settings_change"
	AuditUpdateOffered = "update_offered"
	// AuditExclusionAdd and AuditExclusionRemove record the exclusion list
	// changing; an add's Detail says what was evicted, Bytes the cache bytes.
	AuditExclusionAdd    = "exclusion_add"
	AuditExclusionRemove = "exclusion_remove"
)

// Exclusion kinds.
const (
	ExclusionOrg  = "org"  // every repository of one owner
	ExclusionRepo = "repo" // one repository
)

// Exclusion is an owner or a repository the relay leaves alone: it is kept
// out of the catalog, no hook is installed or pinged for it, its webhook
// deliveries are dropped, and every passthrough answers 404 for it.
type Exclusion struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"` // ExclusionOrg or ExclusionRepo
	Name      string    `json:"name"` // lower case: "owner" or "owner/name"
	Note      string    `json:"note,omitempty"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// ExclusionRequest is the body of POST /admin/exclusions. With dry_run
// nothing changes, and the reply says what an add would remove.
type ExclusionRequest struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Note   string `json:"note,omitempty"`
	DryRun bool   `json:"dry_run,omitempty"`
}

// ExclusionHook is what happened (or, on a dry run, would happen) to one of
// the relay's own webhooks when an exclusion is added. Outcome is one of the
// StepResult outcomes: would_do, done, nothing_to_do or failed.
type ExclusionHook struct {
	Target  string `json:"target"` // owner/repo, or org:<name>
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

// ExclusionResult is the reply to POST /admin/exclusions: what the add
// removed, or on a dry run what it would remove.
type ExclusionResult struct {
	DryRun        bool            `json:"dry_run"`
	Exclusion     *Exclusion      `json:"exclusion,omitempty"` // the new entry; absent on a dry run
	Repos         []string        `json:"repos"`               // catalogued repositories it covers
	Releases      int             `json:"releases"`
	Assets        int             `json:"assets"`
	Images        int             `json:"images"`
	CacheBlobs    int             `json:"cache_blobs"` // blobs no other asset uses
	CacheBytes    int64           `json:"cache_bytes"`
	Pins          int             `json:"pins"`
	Links         int             `json:"links"`          // live share links revoked
	PrefetchRepos []string        `json:"prefetch_repos"` // dropped from the prefetch_repos setting
	Hooks         []ExclusionHook `json:"hooks"`
}

// Status is GET /admin/status — the dashboard.
type Status struct {
	Version         string     `json:"version"`
	Commit          string     `json:"commit"`
	BuildDate       string     `json:"build_date"`
	StartedAt       time.Time  `json:"started_at"`
	GitHubOK        bool       `json:"github_ok"`
	GitHubUser      string     `json:"github_user,omitempty"`
	RateRemaining   int        `json:"rate_remaining"`
	RateLimit       int        `json:"rate_limit"`
	RateReset       time.Time  `json:"rate_reset"`
	LastWebhook     *time.Time `json:"last_webhook_at,omitempty"`
	LastReconcile   *time.Time `json:"last_reconcile_at,omitempty"`
	Repos           int        `json:"repos"`
	Releases        int        `json:"releases"`
	Cache           CacheStats `json:"cache"`
	ReclaimBytes    int64      `json:"reclaim_bytes"`
	Clients         int        `json:"clients"`
	ClientsOnline   int        `json:"clients_online"` // seen in the last 15 min
	CertsExpiring   int        `json:"certs_expiring"` // within 14 days
	DefaultPassword bool       `json:"default_password"`

	// The relay's GitHub token as GitHub reported it (nil until
	// a probe has answered).
	GitHubToken *GitHubToken `json:"github_token,omitempty"`

	// PendingTickets is the enrolments waiting for approval, every app's
	// (the console's Approvals badge).
	PendingTickets int `json:"pending_tickets"`
}

// Event is one message on the console's live stream (GET /events).
type Event struct {
	Type string    `json:"type"` // catalog, cache, client, retention, webhook
	At   time.Time `json:"at"`
	Repo string    `json:"repo,omitempty"`
	Text string    `json:"text"`
}

// GitHub token expiry, backup and
// verification codes.

// GitHubToken is what the relay knows of its own GitHub credential.
// GitHub reports a token's expiry in the github-authentication-token-
// expiration header; a token without one never expires.
type GitHubToken struct {
	Account   string     `json:"account,omitempty"`
	Scopes    []string   `json:"scopes"`
	Kind      string     `json:"kind"` // classic, fine-grained, oauth, unknown
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// DaysLeft is whole days to ExpiresAt (negative once expired); absent
	// for a token without an expiry.
	DaysLeft *int `json:"days_left,omitempty"`
	// Warning: it expires within GitHubTokenWarnDays. Expired: it has.
	Warning bool `json:"warning"`
	Expired bool `json:"expired"`
}

// GitHub token kinds.
const (
	TokenKindClassic     = "classic"
	TokenKindFineGrained = "fine-grained"
	TokenKindOAuth       = "oauth"
	TokenKindUnknown     = "unknown"
)

// GitHubTokenWarnDays is how close to its expiry the token warns.
const GitHubTokenWarnDays = 30

// VerifyCodePrefix starts every verification code: mghv_<id>_<secret>.
const VerifyCodePrefix = "mghv_"

// VerifyCode is a verification code as listed; the code itself is
// shown once, in the create reply.
type VerifyCode struct {
	ID           string     `json:"id"`
	Label        string     `json:"label"`
	CreatedBy    string     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	MaxUses      int        `json:"max_uses"` // 0 = unlimited
	Uses         int        `json:"uses"`
	AllowChanges bool       `json:"allow_changes"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	LastUsedFrom string     `json:"last_used_from,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	Sessions     int        `json:"sessions"`       // live sessions signed in with it
	Code         string     `json:"code,omitempty"` // only in the create reply
}

// Verification describes a verification-code session, in the login reply and
// GET /auth/me.
type Verification struct {
	CodeID       string    `json:"code_id"`
	Label        string    `json:"label"`
	ExpiresAt    time.Time `json:"expires_at"`
	AllowChanges bool      `json:"allow_changes"`
}

// Notices are the banners every console page shows an admin: the GitHub
// token nearing or past its expiry, and each live verification code.
type Notices struct {
	GitHubToken  *GitHubToken `json:"github_token,omitempty"` // only when it warns
	Verification []VerifyCode `json:"verification"`
}

// BackupPassphraseMin is the shortest backup passphrase accepted.
const BackupPassphraseMin = 12

// Audit actions for the GitHub token, backups and verification.
const (
	AuditGitHubToken = "github_token" // a day-band of the token's expiry was reached
	AuditVerify      = "verify"       // a verification code made, used or revoked
	AuditBackup      = "backup"       // a state backup was taken
)
