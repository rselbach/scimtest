# Rust desktop preview

The rewrite runs a native GPUI window and a Rust directory service in one
process. The window follows the original app's gray canvas and sidebar, blue
accents, compact tables, sheets, and system light/dark appearance.

Further native accessibility and exhaustive keyboard testing are deferred as
future improvements. Existing work is documented in
[the accessibility backlog](rust-accessibility.md).

The current build supports:

- Environment configuration for OIDC, SAML, and SCIM, including credentials,
  mappings, provider personas, chooser mode, and certificate validation.
- Users with enterprise fields, managers, custom attributes, and activation.
- Groups and membership editing, search, status filters, pagination,
  selection, bulk deletion, restore, and operation history.
- The Greendale sample and directory tools for generating users, activating
  or deactivating users, deleting users, and clearing local state.
- Go-compatible SQLite state, older SQLite migrations, legacy JSON import, and
  migration from the initial Rust preview. Migrations save private safety copies.
- Version 1 Go-compatible backups through native file dialogs and the API.
  Restores save a safety copy and affect the selected environment.
- Connection config JSON through native copy/save controls, the authenticated
  API, and the original local `/apps/{id}/config.json` download route. Exports
  include the current OIDC/SAML connection values and signing certificate;
  public clients omit their secret. Saved config files use private permissions.
- A token-authenticated local API with 81 implemented operations. API writes
  refresh the native window.

OIDC now supports public discovery/JWKS, authorization code and PKCE,
confidential and public clients, opaque or JWT access tokens, refresh rotation,
client credentials, userinfo, introspection, and revocation. Claim mappings,
enterprise attributes, Entra/Okta/Google personas, and Entra group overage work
through those endpoints. Browser sessions support silent sign-in, authentication
strength, account switching, RP logout, and signed back-channel logout.

The native OIDC inspector runs real HTTP sign-in and refresh exchanges, displays
claims and activity, manages tokens and sessions, and offers signing-key rotation
and certificate validity presets. OIDC token faults can be attached to a flow
or armed for the next sign-in. Signing material and key rings remain compatible
with Go.

Browser choosers preserve the original search/filter list, identifier mode,
login hints, remembered-account selection, requested sign-in method, and separate
Continue and Reuse session forms. Hints can come from query parameters, SAML
requests, or RelayState. Session reuse preserves authentication time; prompt,
maximum-age, and ForceAuthn constraints explain when a fresh sign-in is required.
The browser playground under `/inspect/oidc/{slug}/playground` runs the original
built-in relying-party flow, including public-client PKCE, fault queries,
decoded ID/access tokens, userinfo, refresh rotation, and scope narrowing. It
stays on the local origin when a public tunnel is connected and does not require
registered redirect URIs. Choose **Open browser playground** in the native OIDC
inspector to launch it. The browser result links to a flow inspector with session
and token controls. Browser pages support system light/dark appearance and
narrow windows.

SCIM now supports capability discovery, background sync, reconciliation,
single-resource pushes, progress and cancellation, rate-limit retries, external-ID
adoption, enterprise fields and manager follow-ups, and the Entra PATCH dialect.
The native provisioning screen includes pending changes, job progress, request
traces, connection testing, reset, and remote-import preview/apply with safety
copies and stale-preview detection.

SAML now supports metadata and certificate downloads, mapped attributes and
NameIDs, assertion/response/both signing, pinned SP signatures through POST or
Redirect, and AES-128/192/256-GCM assertion encryption. SAML and OIDC share browser
sessions, authentication strength, and account switching. Single logout supports
both directions and both browser bindings, with signed messages, session matching,
timestamp checks, and correlated results. The native SAML inspector displays raw
XML, Base64, plaintext assertions, sessions, logout results, and validation faults,
including wrapping and NameID-comment forgeries that retain genuine signatures.

The native Traffic screen captures the latest 100 identity exchanges, including
decoded SAML requests and logout transcripts. Runtime controls enable recording,
secret capture, and stdout debugging. Credentials in headers, URLs, forms, JSON,
and SAML auto-post forms are redacted unless secrets are enabled. Raw JWT/SAML
responses and decoded JWT payloads are available with secret capture enabled.
Recording settings and captured traffic stay in memory.

The Fault injection screen offers ten timed scenarios, including token endpoint
outages, slow redemption, and stale JWKS, with injection counts, cancellation,
expiry, recovery decisions, and disarming. Custom faults cover token/assertion
lifetimes, clock skew, signature corruption, claim removal, token errors, SAML
statuses, and all sign-in and back-channel logout tamper options. The local API
preserves the Go fault and scenario request/response formats.

The native Lifecycle screen runs joiner, mover, and leaver workflows with
per-step messages and results. It provisions users before their groups, checks
the next OIDC/userinfo/SAML groups actually issued, handles provider personas
and Entra overage, and deactivates leavers across SCIM, sessions, logout, and
tokens. SAML logout steps open the browser through either binding and settle
when the SP answers. The five Go lifecycle API operations and their browser
checklist URLs use the same run state. Runs stay in memory, capped at ten per
environment.

GitHub enrollment, account gating, public URLs, reconnects, and account switching
are connected to the native app and local API. The account screen opens browser
authorization, displays the verification code and public URL, retries failed
connections, and rotates the installation identity when signing out. A separate
private listener serves only OIDC/SAML through the tunnel; admin APIs and config
downloads remain local. Public sign-in choosers are limited to the installation's
registration network. Tunnel connections honor HTTP(S) proxy environment
variables, HTTP CONNECT and SOCKS5 authentication, and NO_PROXY exclusions.

Native menus provide standard editing and window actions, Help, and What's New.
Save uses Command-S on macOS and Control-S on Linux. Find uses Command-F or
Control-F; Refresh uses Command-R or Control-R. Bundled release notes appear
once per version and can be reopened from Help. The in-app Help menu is also
available on Linux.

Release builds verify the existing Ed25519-signed update feed. Downloads resume
and must match the signed size and SHA-256. The macOS installer stages beside
the installed app, checks its bundle identity, version, architecture, OS
requirement, and notarized Developer ID signature, then rechecks it before an
atomic swap. If the relaunch helper cannot start, it rolls the swap back. A ready
update can be installed on restart or quit; restart waits for SCIM to finish.
Linux offers the matching package for download. Source builds and version
`0.0.0` do not update.

The desktop exposes named inputs, buttons, menus, directory tables, dialogs,
status messages, and inspector payloads through GPUI's AccessKit integration.
Sidebar buttons support keyboard activation. Editor sheets set initial focus,
keep Tab and Shift-Tab inside the sheet, and restore focus on dismissal.
Open sheets hide the workspace from accessibility navigation and expose modal
semantics. Account screens move focus into their controls and restore it on
return, including keyboard reopening from the toolbar. Real tunnel policy-close
and Retry tests cover the production watcher: an account lock closes the editor,
and recovery restores live controls or falls back to the workspace when a
control was recreated. Connection changes within an open Account screen also
validate focus after rendering. Named accessibility groups expose the workspace
and Account focus scopes. Native checks cover policy-close recovery, search
after an interrupted editor, and an account switch with installation identity
rotation using a local test peer.
Password fields keep their values out of the accessibility tree, including
when their visible mask is disabled. Multiline settings use native text-area
semantics. Dropdown triggers expose a press action as well as keyboard opening,
selection, and dismissal.

Native macOS checks cover environment and user editing, Unicode selection and
replacement, Undo, multiline persistence, secret-value privacy, Save and Find
shortcuts, directory rows, dropdown actions, and the local account screen.
Protocol walkthroughs cover OIDC/SAML payloads, token and session controls,
custom faults and injection results, SCIM progress and request traces, remote
import preview/apply, and lifecycle step results and messages. Release notes
expose their text, and lifecycle forms identify group additions and removals.
Automated GPUI tests cover sheet focus, Save/Find, dropdown keyboard behavior,
and revealing focused directory rows while preserving manual scrolling.
Scrollable forms reveal focused inputs; tests traverse all 27 settings fields
with Tab and Shift-Tab at the minimum window size and check multiline caret
visibility. Group member checkboxes also scroll into view. Native macOS checks
cover both fixes, reverse traversal, manual scrolling, and saved membership.
Shared buttons and checkboxes also request visibility when focused, including
fault options, lifecycle group choices, and inspector actions. Native macOS
and Wayland checks verify long forms and their saved effects; Wayland checks
also traverse 16 sessions and end the focused last session. The joiner checks
in this pass cover directory changes, with SCIM disabled in the fixtures.
Long dropdowns constrain their height and reveal their selected entry during
keyboard navigation. Native macOS checks select from 39 active accounts and
41 manager options, verify the resulting sign-in and saved manager, and check
keyboard reopening and Escape without closing the user editor.
Native macOS checks also verify user/group dialog isolation and restoration,
search focus after returning from Account, the Account toolbar keyboard round
trip, and About dismissal with Done or Escape followed by keyboard reopening
from Help. Wayland checks repeat user-dialog isolation, discard confirmation,
saved user recovery, checkbox and choice edits, backdrop clicks, the Account
keyboard round trip, and About dismissal/reopening after parent-window
activation settles. Edited forms ask before Escape or backdrop clicks discard
their drafts; canceling the warning restores the draft and focus. Explicit
Cancel and Close dismiss directly. Text, multiline, checkbox, membership and dropdown changes
keep the warning active even after values are reverted. The twenty app tests
pass on macOS and Linux, including nested confirmation focus, Save suppression,
backdrop gestures and lifecycle form replacement. Native macOS checks cover
all editable form types, invalid drafts, recovered saves and discarded data.
Information windows keep long notes in a selectable scrolling reader above
Done. Wheel, arrow, page and document keys navigate the text. Regressions use
real test-platform resize events and assert the actual 400×280 viewport,
last-block visibility, selection preservation and keyboard Done. Native macOS
and Wayland checks read the final paragraph of 60-chapter notes, reverse
direction and close with Done or Escape. macOS also checks a reduced window;
Wayland checks returning to Help.
Workspace and dropdown regressions also deliver resize events and assert their
actual 960×640 viewport, or 1000×600 for directory rows, before checking geometry
and keyboard behavior.
Linux AT-SPI checks cover text reading, all six EditableText methods, clipboard
copy/cut/paste, Unicode ranges, undo, directory forms, modal focus, shortcuts,
all 27 settings fields, and password privacy. Orca announces the tested fields,
values, selections, and forms. Native Orca walkthroughs also cover OIDC/SAML
sign-in and inspectors, token/session controls, custom and timed faults,
SCIM reconciliation/trace/import, and joiner/mover/leaver forms and results.
The leaver fixture verifies deactivation, session termination, revocation, and
SCIM; its logout delivery steps are skipped without configured endpoints.
Selected sections expose their pressed state. Success and error messages are
announced, including repeated identical identity and SCIM results. The Linux
adapter preserves focus during Orca keyboard grabs, supplies window bounds for
flat review, and reports disabled controls correctly. X11 move/resize and real
focus changes pass. Wayland checks under nested Weston cover environment setup,
Unicode clipboard/undo, protocol inspectors, faults, SCIM, lifecycle runs,
native backup file dialogs, traffic, release notes, and the local account screen
with Orca speech. Directory rows reveal keyboard focus, traffic entries expose
selection, and information windows supply accessible text values. Sign-in uses
the displayed active account after the previous selection is deactivated.
The macOS adapter connects AccessKit to the native keyboard responder. VoiceOver
checks verify workspace/search focus, Account entry/return and reopening, form
focus, discard cancellation, a saved user, repeated command results and repeated
fault-validation errors. Live status text is announced after focus changes from
the same update. Static status/error text advertises as read-only, while
editable fields retain replacement and text selection. Information readers expose
rendered text as read-only text areas, with native selection ranges and glyph
bounds in physical pixels. Native macOS checks select and copy About text and
reveal a selection in chapter 60 of release notes. VoiceOver reads selected text
and current lines, and keyboard Done closes each reader. Clipboard contents and
VoiceOver state are restored. All 1,560 GPUI base tests and twenty desktop tests
pass on macOS; Linux passes twenty desktop tests and four reader regressions
covering selection, Copy, Unicode, stale requests, reflow, reveal and scaling.
The preceding macOS platform fixes also pass eleven platform tests.
Editable inputs now use physical glyph coordinates, including character metrics,
and textareas expose their full accessible value. Native Retina checks verify
Unicode selections and visible highlights through vertical and horizontal
scrolling, plus persistence of 25 custom attributes. Both password fields remain
private before and after mask reveal. VoiceOver reads selected words in the
environment name and a scrolled textarea, and reads the textarea's current line.
VoiceOver is restored to off. These checks use native AX selection requests;
complete screen-reader selection gestures and real display transitions remain
unverified. A regression simulates scale changes from 1 to 2 and back with an
asserted viewport. The current macOS suite passes all 1,561 GPUI base tests,
twenty desktop tests, Clippy and formatting. Linux passes twenty desktop tests
and five input accessibility tests with matching source hashes.
Broader VoiceOver workflows for protocols, provisioning, lifecycle results,
reader links and other controls, native AT-SPI reader selection, and remaining
keyboard coverage are deferred to that future accessibility pass.

Earlier Go/Rust comparison runs covered tunnel enrollment, account switching,
recovery, identity forwarding, local route isolation, and reconnect/restart
stability. These comparisons are historical evidence; their harnesses have been
removed. The previously checked Developer ID signed macOS app and DMG pass startup,
saved-port restart and shutdown checks. ARM64 Debian and RPM packages also pass
installation, native-window, and runtime smoke checks. A final current-source
AMD64 pass repeats these checks on Ubuntu 24.04, Fedora 44, and rolling Arch
under QEMU using binaries cross-compiled on ARM64. Homebrew installs the
current signed artifact with quarantine intact; macOS then blocks it before
Rust starts and reports that Apple could not verify it is free of malware.
The updater's production verifier accepts the existing notarized app and
correctly rejects the new signed but unnotarized Rust candidate. Notarization,
quarantined launch and installation of a notarized Rust update remain part of
beta release validation.
The remaining work is tracked in [the parity checklist](rust-parity.md).

## Run

Use stable Rust. On macOS, install Xcode and its command-line tools. GPUI uses
runtime shader compilation, so the separate offline Metal compiler is not
required. GPUI and its platform adapter use the published `gpui-pre` packages
pinned to `0.3.11`; GPUI components and base controls are pinned to `0.9.0`.

```sh
cargo run --locked -p scimtest-desktop
```

Create an environment, then choose **Load Greendale sample**. Use the row's
pencil button to edit a resource and its **···** menu for history, activation,
or restore. **Set up this environment** opens the configuration sections.
**Tools** provides directory actions and backup save/restore.

The default database is shared with the Go installation:
`<user-config-directory>/scimtest/state.db`. On macOS this is
`~/Library/Application Support/scimtest/state.db`; on Linux it normally
uses `~/.config/scimtest/state.db`.

Choose a different file with `--state-file` or `SCIMTEST_STATE_FILE`:

```sh
cargo run --locked -p scimtest-desktop -- \
  --state-file /tmp/greendale-rust/state.db
```

The preview can read and write current Go schema version 8. Its runtime
shares the Go app's canonical instance lock and acquires it before opening
or migrating state. Because the default path matches the Go app's, installing
the preview over it keeps existing environments. When SQLite state is empty, the preview imports
the sibling `state.json` once, preserving the JSON and saving a private copy.
Old directories without apps become a Default environment so their identities
remain accessible.

Run the same service without a window:

```sh
cargo run --locked -p scimtest-core --bin scimtest -- \
  --state-file /tmp/greendale-rust/state.db
```

The API binds to `127.0.0.1`, preferring its saved port or 8080 and trying the
next 100 ports if that port is occupied. `--port`, `SCIMTEST_PORT`, and the
deprecated `PORT` alias require a fixed port, in that priority order.
`SCIMTEST_STATE_FILE` selects state for either implementation; the Rust alias
also remains supported. `--debug` prints identity traffic; `--debug-secrets`
includes credentials and enables debugging. Go's single-dash flags and `web`,
`help`, and `version` commands are accepted.

A second launch authenticates with the running instance before opening state.
Desktop launches activate its existing window unless `--no-open` is set. A
desktop build refuses to hand off to a headless instance or weaken its GitHub
account requirement. Closing the window, Quit, SIGINT, or SIGTERM cancels
provisioning and the tunnel, drains HTTP connections for up to five seconds,
closes stalled connections, and clears the instance metadata.

Source builds without an application profile stay unlocked and work locally.
Release profiles are supplied at build time with `SCIMTEST_TUNNEL_PROFILE_ID`
(32 lowercase hexadecimal characters), `SCIMTEST_TUNNEL_SERVER` (an HTTP(S)
server URL), and `SCIMTEST_RELEASE_PROFILE_REQUIRED=true`. Desktop builds with a
profile require GitHub enrollment; the headless runner remains available locally
while enrollment is pending. Installation UUIDs and Ed25519 keys are compatible
with Go, preserving existing tunnel reservations across restarts.

The native window has been exercised on macOS and Linux through X11 and
Wayland. Linux desktop builds need GPUI's development libraries and a working
GPU/display. Package and remaining release checks are recorded in
[the parity checklist](rust-parity.md); accessibility has a separate future backlog.

## Local API

Read `<state-file>.lock` for the running instance's `url` and private `token`.
Send `X-Scimtest-Instance-Token` on requests. The API checks the listener's
Host header, rejects cross-origin mutations, and sets `Cache-Control: no-store`.

`GET /api/v1` returns the implemented route catalog and writable fields.
Supported paths include configuration, environments, users, groups, bulk
selection, restore, operation history, directory tools, and backup/restore.
Public protocol endpoints under `/oidc/{slug}` and `/saml/{slug}` do not require the instance
token. They still enforce the local Host boundary. The catalog lists only
implemented management routes. The contract is
specified in [the API guide](api.md).

PATCH preserves omitted fields and accepts explicit `false`, empty strings,
and empty arrays. Unknown fields, recursive nulls, and incorrect types are
errors. Environment capabilities and sync metadata are read-only. Creation
returns `201`; deletion returns a `200` JSON message.

Directory deletion keeps resources pending when SCIM is enabled or remembered
sync state exists. Their remote IDs survive local edits and pending deletes.
Changing the SCIM endpoint resets remote tracking, matching the Go app.

## Verification

The workspace is Rust-only. The Go reference implementation, shared comparison
harnesses, and compatibility suites were removed at the user's request.
Remaining Rust tests cover the local API, saved state, directory operations,
identity flows, SCIM, lifecycle scenarios, tunnel enrollment and recovery,
traffic redaction, update verification, and release signing. Beta testing is
manual; further accessibility work remains a future improvement.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --locked
```

CI tests the services and release tools on Linux and the GPUI desktop on macOS.
The **Desktop packaging** workflow builds an ad-hoc macOS app/DMG and Debian,
RPM, and Arch packages with disposable state. The **Release** workflow uses
Rust for the desktop, tunnel server archives, signed update feed and legacy
Sparkle appcast. See [the server guide](server.md) for the hosted service and
[the migration guide](rust-server-migration.md) before replacing an existing
deployment.

For a beta you can download and test manually, dispatch **Release** on the
rewrite branch. Manual runs build Rust and upload Actions artifacts for
seven days. They use the existing Developer ID signing and notarization steps.
They cannot publish a GitHub release, sign or deploy the stable update feed or
legacy Sparkle appcast, or update the Homebrew cask, even when dispatched on a
tag. Installed stable versions discover updates only through those feeds.

After pushing the branch, start a beta with:

```sh
gh workflow run release.yml --ref rselbach/rust-gpui-rewrite \
  -f version=0.0.0
gh run list --workflow release.yml --branch rselbach/rust-gpui-rewrite
gh run download <run-id> --name scimtest-desktop-release --dir build/rust-beta
```

Wait for the run to finish before downloading. Its **Manual beta downloads**
summary lists the macOS and Linux artifacts. The macOS artifact contains the
signed, notarized ZIP and DMG plus checksums; verify the files with
`shasum -a 256 -c scimtest-desktop_0.0.0_checksums.txt` from the download folder.
The default `0.0.0` also disables the beta's own updater. App versions must have
one to three numeric components; the source commit and Actions build number in
What's New identify each beta. Keep the installed app and extract the beta ZIP
to a separate folder for testing. Quit the installed app before opening the
beta. Rust uses its separate preview state by default, so an ordinary launch
does not migrate the installed Go app's data.

Use manual dispatch for betas; `v*` tag pushes run the normal release pipeline.
Dispatching the signed workflow includes Developer ID signing and notarization.

Build a release executable locally with the public application profile ID:

```sh
SCIMTEST_APPLICATION_PROFILE_ID='<32-character-profile-id>' \
  ./packaging/rust/build-desktop.sh build/scimtest-desktop 0.0.0 macos
```

Use `deb`, `rpm`, or `pkg.tar.zst` instead of `macos` on Linux. The Linux
packaging scripts take the binary, output package, version and architecture;
they declare GPUI's font, window-system, and Vulkan dependencies.
