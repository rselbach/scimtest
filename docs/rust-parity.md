# Rust parity checklist

The Rust app must preserve the existing app's saved data, protocol behavior,
automation API, and desktop workflows. The Go implementation and its acceptance
tests define the current contract. A matching UI or route name does not mark
a feature complete.

- [x] Read and write current Go SQLite state without losing identities,
  credentials, signing material, history, or SCIM state.
- [x] Migrate older Go SQLite state and the initial Rust preview with safety copies.
- [x] Import legacy Go JSON state.
- [x] Port environment configuration, validation, defaults, and secret rules.
- [x] Complete directory attributes, managers, validation, deletion/restore,
  operation history, bulk actions, search, filters, and pagination.
- [x] Match local API requests, responses, errors, authentication, and discovery.
- [x] Read and restore Go version 1 backups, with native save/restore dialogs.
- [x] Match connection/configuration exports.
- [x] Generate and preserve signing keys and certificates; support rotation,
  publication grace periods, and certificate validity controls.
- [x] OIDC discovery, authorization code, PKCE, client authentication, token
  formats, refresh rotation, client credentials, userinfo, introspection,
  revocation, claim mappings, and provider personas.
- [x] Browser chooser, authentication context, shared IdP sessions, silent
  authorization, session reuse, RP logout, and back-channel logout.
- [x] OIDC playground, refresh testing, inspectors, and token/session controls.
  Native and browser playgrounds use real HTTP token exchanges. The browser
  routes preserve local origins, state/nonce/PKCE cookies, OAuth errors,
  decoded tokens, userinfo, refresh rotation and scope narrowing, and fault
  queries. Its flow inspector supports ending sessions and revoking tokens.
- [x] SCIM capability discovery, sync planning, provisioning, reconciliation,
  per-resource push, cancellation/progress, rate limiting, enterprise values,
  manager ordering, Entra dialect, reset, traces, and remote import previews.
- [x] SAML metadata, certificate downloads, sign-in, attribute/NameID mappings,
  assertion/response signing, pinned SP signatures, and assertion encryption.
- [x] SAML logout through Redirect and POST bindings in both directions.
- [x] Traffic capture/redaction, flow activity, raw and decoded payloads,
  and diagnostics.
- [x] Complete fault injection, timed resilience presets, and tamper scenarios.
- [x] Joiner, mover, and leaver scenarios with per-step results.
- [x] GitHub enrollment, installation authentication, account gating,
  reconnects, stable public URLs, and account switching/logout.
- [x] Runtime options, stable ports, instance handoff, and shutdown behavior.
- [x] Native menus/shortcuts, Help, and What's New.

Further native accessibility and exhaustive keyboard-navigation checks are
deferred as future improvements at the user’s request. Existing work and
remaining checks are recorded in [the accessibility backlog](rust-accessibility.md).

- [x] Signed update feed verification, resumable downloads, macOS staging,
  code signature verification, atomic installation, rollback, and restart.
- [ ] Signed macOS app/DMG, Homebrew, Linux packages, and release smoke tests.
  The current app and DMG are Developer ID signed with the hardened runtime
  and secure timestamps. Both
  passed startup, saved-port restart, and shutdown checks, including execution
  from the mounted DMG. Homebrew installs the same signed executable and retains
  quarantine. Its CLI preflight waits before Rust starts: the native Gatekeeper
  dialog says Apple could not verify the app is free of malware. The smoke tool
  now bounds that preflight reliably. The production updater verifier accepts
  the existing notarized app and rejects the signed but unnotarized Rust
  candidate. Notarization remains pending at the user's request, along with
  quarantined launch and installation of a notarized Rust update. No Gatekeeper
  approval or quarantine bypass was used.
  Linux ARM64 Debian
  and Fedora 44 RPM packages build, install, open native GPUI windows, and
  pass runtime smoke checks under Xvfb with release account gating. The RPM
  requires Wayland library capabilities so Fedora's renamed packages resolve.
  AMD64 Debian, Fedora RPM, and Arch packages also build, install, open native
  GPUI windows, and pass startup, saved-port restart, and shutdown under QEMU.
  The final package pass uses current source on Ubuntu 24.04, Fedora 44 and
  rolling Arch, with 589 matching source files recorded before compilation.
  Their binaries are cross-compiled using the native ARM64 compiler because
  emulated rustc crashes. These checks use synthetic release profiles and
  disposable state; no release was published.
  An Arch follow-up checks root ownership, payload modes, expected contents,
  and package metadata before repeating installation and runtime checks.
- [x] Shared acceptance coverage verifies the Rust and Go implementations
  against the same behavior before existing installations switch.
  Eleven original API scenarios and seven shared browser/workflow scenarios now
  run against both implementations in core CI. They cover chooser submission,
  session reuse, SAML logout in both directions/bindings with independent
  signature checks, playground validation, faults, and SCIM lifecycle runs.
  Browser RP coverage includes confidential credentials with special characters,
  public-client PKCE, callbacks, refresh, and inspector controls. Three shared
  tunnel scenarios additionally verify enrollment, account switching, revoked
  installations and retry, public OIDC exchanges, local-only routes, chooser
  network restrictions, reconnects, and installation identity after restart.
  They use a real WebSocket peer with independent Go signature verification.
  Rust also passes a separate interoperability test with the actual Go server.
  The final combined current-source suite passes 171 Rust tests: 126 core,
  two protocol and 43 server tests. The current desktop release checkpoint
  separately passes twenty app tests.

- [x] Implement the public tunnel service in Rust and verify its compatibility
  and migration. The `scimtest-server` crate implements Go-compatible
  application profiles, dashboard sessions, installation enrollment/revocation,
  stable reservations, idle cleanup, route rules, key parsing and rate limits.
  Tests exchange real state with Go in both directions and compare route/key
  behavior against the Go implementation. Failed writes preserve in-memory
  state. The executable now serves HTTP health/readiness, aggregate metrics,
  the existing landing page and signed WebSocket tunnels. Real Go clients
  forward binary requests and responses through
  Rust using both enrolled and legacy signatures. Socket checks cover preserved
  reservations, route/host/origin boundaries, proxy trust, hop headers, duplicate
  and capacity rejection, body limits, status clamping and in-flight disconnects.
  Registration keeps its 64 KiB limit before authentication, then raises the
  buffered socket's limit for normal traffic. HTTP response writes have the Go
  deadline; blocking write and buffered-frame regressions pass. CLI checks load
  actual Go state, stop with SIGTERM, reuse the port and preserve the file exactly.
  The client and server share `scimtest-protocol`; existing Rust-client tests
  retain interoperability with the Go service.
  GitHub OAuth now implements PKCE, expiring single-use state, host-only cookies,
  admin dashboard sessions and logout. Installation authorization supports both
  code comparison and single-use browser handoff, polling and grants bound to
  the exact key and legacy identifier. Replacement respects GitHub account
  ownership, counts approved but unconnected setups, and revokes/disconnects
  the selected installation. Dashboard controls manage profiles, reservations,
  revocations and live tunnels with CSRF protection; pages preserve the Go
  styles and copy with escaped template values. GitHub tokens stay on the
  server. Enrollment credentials stay in memory and are excluded from saved
  state and the desktop's account information.
  Real Go clients now enroll, poll, redeem and forward through Rust. The current
  Rust client also covers enrollment, revocation/retry, Troy-to-Abed account
  switching with identity rotation, and stable URLs after a client restart.
  Other tests exercise replay, wrong-key grants, concurrent redemption,
  failed-write rollback, CSRF, ownership, expiration and network limits.
  Current macOS and Linux ARM64 checks pass 43 server tests, two protocol tests,
  ten client/export regressions, Clippy across the service crates,
  and Go race tests for the server/auth/client/protocol/header packages. Shared
  policies retain 421 route/key comparisons and add 342 confirmation-origin
  and 36 enrollment-status/network comparisons against Go. Current service,
  template, shared protocol and fixture source hashes match across platforms.
  Five shared acceptance tests run the same dashboard, installation and
  replacement workflows through the full Go and Rust servers, including 75
  complete-router comparisons for methods, malformed forms and privacy headers.
  The same browser workflow passes against both: OAuth cookies, profile edits,
  confirmation/cancellation, enrollment, narrow layouts, live refresh,
  replacement, revocation/restoration, saved-name release and logout.
  The live executable rehearsal preserves both running clients through
  Go → Rust → Go rollback → Rust. It checks OIDC exchanges, SAML metadata,
  signing keys, public URLs, sessions, revocations and state written in both
  directions. It also checks failed candidate preflight and pending enrollment
  loss on restart. The rehearsal exposed an older Go-server ordering race;
  Rust now queues bounded early traffic until registration succeeds. Tests
  reject excess count/bytes without forwarding and accept legal large frames.
  GitHub uses a local authorization/token/user provider; no live OAuth account
  was used. These checks cover macOS and Linux ARM64. The same service and
  client groups also pass for static Linux AMD64 under QEMU. Separate executable
  rehearsals verify migration and restart against the exact standalone release
  artifact, whose hash remains unchanged throughout the checks.
  The deployed service remains Go. Deployment
  remains a separate action; see [the migration guide](rust-server-migration.md).
- [x] Validate the hosted Rust service on Linux AMD64, the current deployment
  target. A native ARM64 compiler builds `x86_64-unknown-linux-musl` release
  executables, which run under QEMU. ELF checks verify AMD64 architecture and
  no interpreter or shared-library dependencies. The 43 server, two protocol
  and ten client/export tests pass, including both real clients, shared hosted
  workflows and migration/rollback. The exact standalone release executable
  also passes migration and saved-state restart/shutdown checks. A new native
  AMD64 CI job preserves these checks; remote CI has not run for this change.
