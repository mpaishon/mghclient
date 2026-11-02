# Onboarding an app onto mghRelay

This guide puts a new application behind the relay so that it updates from
it instead of from GitHub. It is a checklist, written from onboarding
CCManager, the first app. For the SDK's API in detail, see
[README.md](README.md). The relay's design and API live in the relay's
repository (MyGHAgent: `docs/UPGRADE_GATEWAY.md`, `docs/API.md`).

**Who does what**

| Side | Responsible for |
|---|---|
| The relay | Which release each instance is offered (channel, promotion, hold, audience), which instances may exist (enrolment), and serving the bytes |
| The app | Asking (`Check`/`Run`), verifying (the SDK does it), installing, and saying how the install went (`Report`) |

Installing, staging, restarting and rolling back stay the app's own business.
The SDK never touches the app's binary.

**Reference implementation:** CCManager (`github.com/mpaishon/CCManager`).
- `internal/update/relay.go`: the update source.
- `internal/cli/relay.go`: the CLI.
- `internal/cli/relayctl.go`: the console's manager.
- `frontend/src/pages/RelayTab.jsx`: the panel.

Copy from it freely.

---

## 0. Before you start

- [ ] The app is a **Go** program built with **Go 1.27.3+** (`go 1.27.3` in its `go.mod`). For other languages, see §9.
- [ ] Its releases are **GitHub releases** in a repository the relay syncs:
      the owner is in the relay's `[github] owners`.
- [ ] You have an admin sign-in to the relay console. A token with the
      `apps:write` and `enroll:approve` scopes also works for scripting.
- [ ] You have picked a **slug**: 2–32 characters, lower case, digits and
      `-`, starting with a letter or digit (e.g. `ccmanager`). The slug is
      fixed for the app's life. It is compiled into the app and is part of
      every route.

## 1. Name the release assets

The relay finds an instance's asset by name. The default needs no
configuration:

```
<slug>-<tag>-<goos>-<goarch>.<ext>      e.g. ccmanager-v2026.11.02-darwin-arm64.zip
```

- `<tag>` is the release tag exactly, e.g. `v2026.11.02`.
- `<goos>-<goarch>` is Go's (`linux-amd64`, `darwin-arm64`, `windows-amd64`, …).
  The SDK reports `runtime.GOOS-runtime.GOARCH` unless `Config.Platform`
  says otherwise.
- Tags must order as versions (`vYYYY.MM.DD[.N]`, or semver). The relay
  never offers a downgrade.

If the app already names its assets another way, set the app's **asset
pattern** in the console instead, using `{name}`, `{version}`, `{os}`,
`{arch}` and `{ext}`. For example, `{name}_{version}_{os}_{arch}.{ext}`.

**Check:** a published release has one asset per platform you ship, and
nothing else matches the pattern twice.

## 2. Add the SDK to the app

```sh
go get github.com/mpaishon/mghclient@latest
go mod tidy
```

- `github.com/mpaishon/mghclient` is a **public** module with semver tags
  (`v0.1.0`, …): no `GOPRIVATE`, no git credentials, and it builds in CI
  and Dockerfile stages like any other dependency.
- `go.mod` records the tag; move it on deliberately (`go get …@v0.2.0`)
  and read the release notes while it is `v0`.

## 3. Wire the SDK into the app

### 3.1 Configuration (one place)

```go
func relayConfig(stateDir string) mghclient.Config {
    return mghclient.Config{
        App:      "myapp",                              // the slug, compiled in
        StateDir: filepath.Join(stateDir, "relay"),     // a folder of its own
        Version:  buildinfo.Version,                    // the running tag
        // SigningKeys: []ed25519.PublicKey{releasePub}, // §6, optional
    }
}
```

- `StateDir` must belong to this app alone; never share one with
  `mghagent` or another app. The key in it never leaves the machine.
  Keep it under the app's data folder so it survives upgrades.
- `Version` must be the release tag the binary was built as. A
  development build (`dev`) is never offered an update, and installs
  nothing without forcing.

### 3.2 Choose the source

Use the relay while the app is enrolled, and the app's previous source
(GitHub, say) otherwise. Enrolling switches the app over and forgetting
switches it back, with no configuration flag:

```go
if mghclient.StatusOf(cfg) == mghclient.Enrolled {
    inst, err := mghclient.Open(cfg)
    // ... use the relay
}
```

If the app has an update abstraction (CCManager's `update.Source`), write
the relay as one more implementation of it. Then the download, verify,
stage, swap and rollback steps stay shared with the GitHub path. See
CCManager's `internal/update/relay.go` (about 100 lines) and README.md §5.

### 3.3 Enrolment UX (required)

An instance has to be enrolled once, by a person. Provide **both** of these:

1. **A CLI** for headless hosts and scripts (CCManager's `--relay`):
   - `--relay --enrol <https://relay:8444> [--code X] [--fingerprint F]`
   - `--relay` shows the status, and collects an approved request
   - `--relay --wait` resumes waiting for approval
   - `--relay --forget` removes the enrolment
2. **A UI panel** if the app has one (CCManager's Settings › Relay updates).

Either one must:

- [ ] **Show the certificate fingerprint before sending anything.**
      `mghclient.Probe(ctx, url)` returns it. If `trusted` is false, make
      the user compare it with the relay console (Apps › app › Enrol), and
      pass it as `AcceptFingerprint`. Never auto-accept it.
- [ ] **Offer both a code and approval.** A non-empty code enrols at
      once; leave it empty to make a request.
- [ ] **Show the pairing code prominently** while a request waits
      (`Pending.Pairing`, from `OnPending` or `PendingRequest(cfg)`). Tell
      the user to approve only the request showing the same code.
- [ ] **Wait in the background, and resume after a restart.** Calling
      `Enrol(ctx, cfg, EnrolOptions{})` with no URL resumes a waiting
      request. Don't start a new one, or the relay sees two requests.
- [ ] **Explain `ErrDenied`:** the request was denied, or lapsed after 72 h
      by default. Offer to ask again.
- [ ] **Forget:** remove `StateDir`, then tell the user to also revoke the
      instance in the relay console.
- [ ] **Accept the address with or without a trailing slash.** Accept the
      fingerprint with or without colons, in either case.

In a web console, put the write actions (enrol, install, forget) behind
the app's strongest admin check. The relay decides which binary this host
runs, so a temporary or read-only session must not be able to change it.
CCManager puts those routes on its verification never-list.

### 3.4 Check, install, report

The simplest way is to hand the loop to `inst.Run(ctx, RunOptions{…})`. To
keep the latest offer for a UI, write the loop yourself, as CCManager's
`relayManager.loop` does:

```go
reply, err := inst.Report(ctx, mghclient.Report{UpdateState: state, Detail: detail})
// reply.Offer: nil = up to date; otherwise what to install
// wait inst.Every() (the relay's schedule), 1 min after an error
// inst.RenewIfDue(ctx) about twice a day; ErrRevoked from any call = stop
```

- **Honour `offer.Policy`.** With `automatic`, install without asking, but
  only once per version: if that install fails, wait for the user. With
  `notify`, show it and install when asked.
- **Download with `inst.Download` or `inst.DownloadFile`.** It checks the
  SHA-256 as it streams, and the signature before fetching (§6). On any
  error, throw the bytes away.
- **Report the update state** as it changes, using these states:

  | State | When |
  |---|---|
  | `StateStaged` | Downloaded, verified and ready to apply |
  | `StateSwapped` | Running the new version for the first time |
  | `StateConfirmed` | The new version has proved healthy |
  | `StateRolledBack` | The new version failed and the old one is back (`Detail`: why) |
  | `StateFailed` | The update could not be applied (`Detail`: why) |

  If the app records its update progress (CCManager's marker file),
  derive the state from that record on every report rather than tracking
  it twice.
- **Report right after an install.** That way the relay console shows it
  without waiting for the next cycle.

## 4. Release it

1. Cut a release of the app containing the SDK, the usual way.
   Instances **must already run a relay-aware version** before they can
   be enrolled, so this release still goes out through the app's old
   update path, GitHub.
2. Check the release's asset names against §1.

## 5. Create the app on the relay

**Console:** Apps › **Add app**.

| Field | Value |
|---|---|
| Name | Display name, e.g. `CCManager` |
| Slug | As compiled in (§0) |
| Repository | `owner/repo`. The form checks that the relay sees it and counts its releases. |
| Enrolment | **Request, I approve here** (usual); **Auto-approve from the local network** for zero-touch LAN installs; **Code only** for scripted installs |
| Promotion | **Automatic**: offer each release as GitHub publishes it. **Manual**: offer only what you promote on the Releases tab. |
| Audience | Both, internal only, or external only |
| Update policy | Empty means the relay's default; `automatic` or `notify` |
| Signing key | Optional, see §6 |

**Or the API**, with a token holding `apps:write`:

```sh
curl -sS -X POST https://<relay>:8444/ui/api/admin/apps/check-repo \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"repo":"owner/repo"}'                       # → {"visible":true,"releases":N}

curl -sS -X POST https://<relay>:8444/ui/api/admin/apps \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"slug":"myapp","name":"My App","repo":"owner/repo",
       "promotion":"automatic","audience":"both","enrol_policy":"approve","enabled":true}'
```

**Check:** the app's page shows the newest release as **Latest**, and
**Offered** is the same tag.

## 6. Signed releases (optional, recommended for anything internet-facing)

Mutual TLS plus the digest already protect against everything except a
compromised relay. A signature protects against that too.

1. Make an Ed25519 key pair once (`ed25519.GenerateKey`) and keep the
   private half out of the repository and vaulted. **Losing it means every
   instance needs a manual reinstall** to trust a new key: this has
   already happened once with mghagent.
2. For each asset at release time, run
   `mghclient.SignRelease(priv, tag, goos+"-"+goarch, sha256hex)` and
   publish the result as `<asset>.sig`.
3. Put the public key (hex) in the app's **Signing key** on the relay.
   The relay then offers only releases that carry a `.sig`.
4. Compile the public key into the app as `Config.SigningKeys`. The SDK
   refuses an unsigned or badly signed offer (`ErrBadSignature`) before
   downloading.

## 7. First instance: verify end to end

1. On a host running the relay-aware version, enrol it (UI or CLI) with
   the relay's **LAN address**: `https://<nas>:8444`, not the public name,
   which isn't served yet.
2. On the relay, open **Approvals** and approve the request whose
   **pairing code** matches. Name it after the host.
3. The instance shows **Enrolled**, and within a cycle the relay's Apps ›
   app › Instances lists it with its version.
4. Publish a new release, or promote one. The instance shows the offer.
   Install it and watch the instance's state go `staged → swapped →
   confirmed` on the relay.
5. **Revoke a test instance**: on the relay's Instances tab, choose Revoke.
   The instance's next call gets `ErrRevoked`, and it should say so
   plainly.

**Clean up after testing:** revoke throwaway instances, and deny stray
requests. The API cannot revoke: that route needs a console sign-in.

## 8. Onboarding checklist (copy into the app's PR)

```
- [ ] Assets named <slug>-<tag>-<goos>-<goarch>.<ext> (or asset pattern set)
- [ ] SDK added: github.com/mpaishon/mghclient at a tagged version
- [ ] Config: slug, own StateDir, Version = release tag
- [ ] Relay used while enrolled, old source otherwise
- [ ] Enrol CLI: --enrol/--code/--fingerprint, status, --wait, --forget
- [ ] Enrol UI (if the app has one): fingerprint compare, code or request,
      pairing code shown, background wait that resumes, forget
- [ ] UI write actions admin-only (not for temporary/read-only sessions)
- [ ] Offer handled per policy (automatic once / notify)
- [ ] Download via SDK; bytes discarded on any error
- [ ] Update state reported: staged, swapped, confirmed, rolled_back, failed
- [ ] ErrRevoked / ErrDenied / ErrNotEnrolled explained to the user
- [ ] Release published through the old path; assets checked
- [ ] App created on the relay; Latest = Offered
- [ ] (Optional) signing key: private half vaulted, public in app + relay
- [ ] First instance enrolled, updated end to end, test instances revoked
- [ ] App docs: how to enrol, how to forget, where the state folder is
```

## 9. Apps not written in Go

There is no SDK for other languages yet. The protocol is plain HTTPS +
JSON with mutual TLS; the relay's `docs/API.md`, under "Upgrade
gateway", has the routes:

- `POST /ui/api/enroll`, on the console port, with `{app, csr_pem,
  hostname, os, arch, version}` and an optional `code`. It answers `200`
  with the certificate, or `202` with a ticket to poll at
  `GET /ui/api/enroll/ticket/<token>`.
- `GET /relay/apps/<app>/update?platform=…&current=…`, then
  `GET /relay/apps/<app>/assets/<id>`. Both use the relay port with the
  client certificate.
- `POST /relay/apps/<app>/report`.

Porting `mghclient` means reproducing:
- the CSR and key handling;
- fingerprint pinning of the console certificate;
- trusting only the relay's CA on the relay port;
- certificate renewal;
- signature checking (`"MyGHAgent client release\n<tag>\n<goos-arch>\n<sha256>\n"`).

Raise it before starting.
