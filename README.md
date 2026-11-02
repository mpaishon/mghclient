# mghclient — updating an app through mghRelay

`github.com/mpaishon/mghclient` is the client SDK for an application that
gets its updates from an **mghRelay**, a self-hosted relay in front of
GitHub releases. It does four things: **enrol** the instance once,
**check** for an update, **download** it with its digest (and signature)
verified, and **report** what the instance runs. Installing, staging and
restarting stay the application's business.

Mutual TLS, certificate renewal, revocation handling, LAN/WAN address
selection and a private state folder come with it.

**Onboarding a new app?** Follow [ONBOARDING.md](ONBOARDING.md); this page
is the SDK's reference.

## 1. Adding the module

```sh
go get github.com/mpaishon/mghclient@latest   # or a tag, e.g. @v0.1.0
```

It is a public module: no `GOPRIVATE`, no git credentials. It needs
Go 1.27.3 or newer and pulls in only logrus (for its renewal log line) and
`golang.org/x/sys`.

```go
import "github.com/mpaishon/mghclient"

cfg := mghclient.Config{
    App:      "myapp",                          // the app's slug on the relay
    StateDir: filepath.Join(dataDir, "relay"),  // a folder of its own; made private
    Version:  buildinfo.Version,                // the release tag, e.g. "v2026.11.01"
    // SigningKeys: []ed25519.PublicKey{releasePub}, // when the app signs (§4)
}
```

## 2. Enrolling

```go
// Show the fingerprint before sending anything.
fp, trusted, err := mghclient.Probe(ctx, relayURL)
// If !trusted, show fp and ask the user to compare it with the console's
// Enrol tab.

inst, err := mghclient.Enrol(ctx, cfg, mghclient.EnrolOptions{
    URL:               relayURL,          // https://relay.home.lan:8444
    Code:              code,              // "" asks for approval instead
    AcceptFingerprint: fp,                // once the user has confirmed it
    OnPending: func(p mghclient.Pending) {
        // Show the pairing code: the console shows the same one beside the
        // request, and the admin approves only when they match.
        ui.Status("Waiting for approval on the relay. Pairing code " + p.Pairing)
    },
})
switch {
case errors.Is(err, mghclient.ErrDenied):
    ui.Error("Not approved by the relay administrator.")
case err != nil:
    ui.Error(err.Error())
}
```

- **With a code** the call returns at once.
- **Without** it blocks, polling every 30 s (5 min after the first hour),
  until the request is approved, denied (`ErrDenied`; expired reads the
  same), or `ctx` ends. The key and the poll token wait in the state folder
  (both `0600`), so if the app restarts, calling `Enrol` again **resumes**
  the same request rather than asking again. `StatusOf(cfg)` says
  `NotEnrolled`, `Waiting` or `Enrolled`.
- `NoWait: true` returns `ErrPending` straight after the request (or after
  one poll of a waiting one), for an app that would rather call `Enrol`
  again on its own timer.
- An app set to *auto-approve from the local network* enrols at once from
  the LAN (never through a forwarder on the relay's own host: a loopback
  peer always queues).
- If the relay answers that enrolment is closed to this network (the
  laptop roamed outside), the request is kept and polling goes on.
- `Force: true` throws away an existing enrolment or request first.

At later starts:

```go
inst, err := mghclient.Open(cfg) // ErrNotEnrolled → show the Enrol screen
```

## 3. Checking, downloading, reporting

The simplest app hands the loop to `Run`:

```go
go inst.Run(ctx, mghclient.RunOptions{
    State:   func() string { return updater.State() }, // "", staged, swapped, confirmed, rolled_back, failed
    OnOffer: func(o *mghclient.Offer) {
        switch o.Policy {
        case mghclient.PolicyAutomatic:
            updater.Install(o)            // download, stage, restart when idle
        case mghclient.PolicyNotify:
            ui.Banner(o.Version + " is available")
        }
    },
    Now: checkNow, // a channel the UI's "Check now" writes to
})
```

`Run` reports every cycle (`POST /relay/apps/<app>/report`), acts on the
offer the reply carries, waits as long as the relay says (5 min by default),
renews the certificate when due, and returns `ErrRevoked` if the relay stops
honouring the instance.

Or call the pieces yourself:

| Call | Does |
|---|---|
| `inst.Check(ctx)` | The `*Offer` for this version and platform, or nil. |
| `inst.Download(ctx, offer, w, progress)` | Streams the asset to `w`, checking the SHA-256 as it goes and the signature (when `SigningKeys` is set) **before** fetching. On any error, discard what was written. |
| `inst.DownloadFile(ctx, offer, path, progress)` | The same into `path.part`, renamed into place only when verified. |
| `inst.Report(ctx, mghclient.Report{UpdateState: mghclient.StateConfirmed})` | Tells the console what runs; the reply carries the offer. |
| `inst.SetVersion(v)` | After an in-place swap without a restart. |
| `inst.Releases(ctx)` | The releases this instance may see. |
| `inst.RenewIfDue(ctx)` | Renews the certificate in its window (Run does this). |

An `Offer` is `{app, version, channel, policy, platform, asset_id, name,
size, sha256, signature?, published_at}`. `policy` is the resolved one
(instance → app → household): `automatic` installs without asking, `notify`
asks first. The relay never offers a downgrade, nothing while the instance is
**held**, and nothing it would not let the instance download.

Report the update states as they happen — `staged` once downloaded and
verified, `swapped` on first start of the new version, `confirmed` when it is
healthy, `rolled_back` / `failed` otherwise — and the app's Instances tab
shows where every instance stands.

## 4. Signing releases (optional)

Mutual TLS plus the digest is enough on the LAN. To also defend against a
compromised relay, sign each asset:

1. Make a key once: an Ed25519 key pair (`ed25519.GenerateKey`); keep the
   private half out of the repository.
2. In the release build, for each asset:
   `sig, _ := mghclient.SignRelease(priv, tag, goos+"-"+goarch, sha256hex)`
   and publish it as the asset `<asset name>.sig` (the base64 line only).
3. Put the public key (hex) in the app's **Signing key** in the console: the
   relay then offers only releases that carry a `.sig` (it never verifies
   it — that is the instance's job).
4. Compile the public key into the app: `Config.SigningKeys`. The SDK refuses
   an offer without a valid signature (`ErrBadSignature`) before downloading.

The signed message is `"MyGHAgent client release\n<tag>\n<goos-arch>\n<sha256>\n"`,
the same format `mghagent` uses.

## 5. Plugging into an existing updater

If the app already has an update abstraction (a "source" that finds a
release and opens its asset), the relay is one more implementation of it,
and the download, verify, stage, swap and rollback steps stay shared with
the GitHub path. A sketch, for a `Source` with `Release(ctx, tag)` and
`Download(ctx, asset)`:

```go
type relaySource struct{ inst *mghclient.Instance; offers map[int64]*mghclient.Offer }

func (s *relaySource) Release(ctx context.Context, tag string) (update.Release, error) {
    o, err := s.inst.Check(ctx)       // the relay decides what is on offer
    if err != nil {
        return update.Release{}, err
    }
    if o == nil || (tag != "" && o.Version != tag) {
        return update.Release{}, update.ErrUpToDate
    }
    s.offers[o.AssetID] = o
    return update.Release{Tag: o.Version, Asset: update.Asset{
        Name: o.Name, URL: "relay:" + strconv.FormatInt(o.AssetID, 10), Size: o.Size, SHA256: o.SHA256,
    }}, nil
}

func (s *relaySource) Download(ctx context.Context, a update.Asset) (io.ReadCloser, error) {
    id, _ := strconv.ParseInt(strings.TrimPrefix(a.URL, "relay:"), 10, 64)
    o := s.offers[id]
    pr, pw := io.Pipe()
    go func() { pw.CloseWithError(s.inst.Download(ctx, o, pw, nil)) }()
    return pr, nil // a digest or signature failure surfaces as the read error
}
```

Report `staged` / `swapped` / `confirmed` from the updater's own record of
its progress, and keep the old source for hosts that are not enrolled.

## 6. Errors

| Error | Meaning | What the app does |
|---|---|---|
| `ErrNotEnrolled` | No enrolment in the state folder | Show the Enrol screen |
| `ErrPending` | Request waiting (`NoWait`) | Show "waiting"; call `Enrol` again later |
| `ErrDenied` | Not approved (denied or lapsed) | Say so; offer to ask again |
| `ErrRevoked` | The relay no longer honours the certificate | Clear the state folder (`Force`), show Enrol |
| `ErrBadSignature` | Offer not signed by a compiled-in key | Do not install; report `failed` |
| `ErrSHAMismatch` | Bytes do not match the digest | Do not install; retry later |
| `ErrWrongApp` | The state folder belongs to another app | Use a folder per app |
| other | Network, relay down, rate limit | Retry on the next cycle |

## 7. The state folder

| File | |
|---|---|
| `client.key` | The private key, `0600`; never leaves the machine |
| `client.crt`, `ca.crt` | The certificate and the relay's CA (the only trust used) |
| `state.json` | Who the instance is, where the relay is (written last) |
| `pending.json`, `pending.key` | A request waiting for approval (`0600`); removed once decided |

On Windows the folder gets an owner-only ACL. Do not share one folder
between apps or with `mghagent`.

## Versions and where the code lives

The module follows semantic versioning from `v0.1.0`; while it is `v0`, a
minor version may change the API, and the release notes say how.

This repository is **exported** from the relay's own repository, where the
SDK is maintained beside the server it talks to (so the two are tested
together). Don't edit files here: changes are made upstream and arrive in
the next export. Issues are welcome.
