# Rust parity checklist

The Rust app must preserve the existing app's saved data, protocol behavior,
automation API, and desktop workflows. The implementation, remaining Rust tests,
and manual beta checks define the current acceptance process. A matching UI or
route name does not mark a feature complete.

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
  Packaging now builds Rust throughout. Manual beta workflows sign and notarize
  the macOS app/DMG and upload downloads without publishing stable updates.
  The replacement beta build and manual testing remain pending. Previous
  signing/package checks are historical evidence for their recorded revisions.

- [x] Public tunnel service implemented in Rust, including application
  profiles, stable reservations, enrollment/revocation, GitHub OAuth,
  dashboard controls, signed WebSocket tunnels, route/network limits and
  persistence. Remaining Rust tests cover server and client workflows.
- [x] Configure static Linux AMD64 server checks and Rust server archives for
  Linux/macOS on AMD64 and ARM64.

The Go implementation and compatibility suites were removed at the user's
request. Earlier comparison evidence is historical; current builds and tests
require Rust only. Manual beta testing is the next acceptance step. Existing
legacy SQLite/JSON import and wire-format support remain implemented.
