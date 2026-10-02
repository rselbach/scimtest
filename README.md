# scimtest

`scimtest` is a local auth testing service: it plays the identity provider
(and SCIM client) so you can test your app's SAML, OIDC, and SCIM
implementations without touching a real IDP. It combines:

- an OIDC authorization-code test IDP
- a SAML HTTP-POST test IDP
- a SCIM sync control surface for local users and groups

Everything runs in a local web UI or through the [local JSON API](docs/api.md).
Agents can configure environments, manage directories, run protocol flows,
sync SCIM resources, and inspect results without a browser. See
[Automate a local instance](docs/automation.md) for a complete example.
The bundled [scimtest agent skill](.agents/skills/scimtest/SKILL.md) provides
operating instructions and an API helper. Copy its directory into your agent's
skills directory to use it outside this checkout.
Each environment owns its users and
groups in SQLite and supplies that environment's OIDC claims, SAML
attributes, and optional SCIM provisioning, along with independent
credentials, remote IDs, sync state, operation history, and errors.

## Install

On macOS, install the signed app with Homebrew:

```sh
brew install --cask rselbach/tap/scimtest-desktop
```

On Linux amd64, download the package for your distribution from the
[releases page](https://github.com/rselbach/scimtest/releases), then install it.

Ubuntu 24.04:

```sh
sudo apt install ./scimtest-desktop_<version>_linux_amd64.deb
```

Fedora 44:

```sh
sudo dnf install ./scimtest-desktop_<version>_linux_x86_64.rpm
```

Arch Linux:

```sh
sudo pacman -U ./scimtest-desktop_<version>_linux_x86_64.pkg.tar.zst
```

The releases page also provides an Apple silicon macOS 26+ DMG and ZIP. Tagged
releases no longer distribute the command-line application.

The signed macOS app uses Sparkle for updates. After installing a
Sparkle-enabled release, choose **scimtest > Check for Updates…** or allow
automatic checks when prompted.

Running from source also works, but source builds have no embedded tunnel
identity, so the public tunnel is unavailable and OIDC/SAML are served on
this machine only:

```sh
go run ./cmd/scimtest
```

### Desktop app

The native WebView app reuses the same Go server and embedded UI without an
Electron or JavaScript rewrite. It requires a GitHub account linked in the app
before the admin UI or local test endpoints unlock. See
[the desktop documentation](docs/desktop.md) for preview artifacts, local build
steps, the authentication design, and release packaging details.

## Quick start

1. Open scimtest. A first run lands directly on the environment wizard.
2. Name the environment, enable the protocols you need, and save — the
   OIDC and SAML connection values (issuer, discovery, metadata, and
   certificate) appear as you type and can be copied or downloaded.
3. Load the Greendale sample (from the empty users list or Bulk tools) to
   get ten named users and three overlapping groups instantly.
4. Test: use **Test sign-in** for a real flow against your app, the
   built-in **playground** for an instant OIDC round trip with no relying
   party required, or **Sync** to push the directory to your app's SCIM
   endpoint.

## Features

- **Local automation API.** `/api/v1` lists the available operations. The API
  uses the running instance's private token, addresses environments explicitly,
  and returns JSON results and errors. It works in both source and desktop
  builds and is available only on the local listener.
- **Environments.** Each environment is one app you are testing, with its
  own directory, credentials, and protocol configuration. The environment
  selector in the top bar sets the context for the whole admin UI.
- **OIDC playground.** A built-in relying party that runs the full
  authorization-code exchange and shows the token response, decoded and
  raw ID token, and userinfo on one page. It requests `offline_access`, so
  the page can also redeem the refresh token, optionally with a narrower
  scope, and show the refreshed claims beside the ones they replace.
- **Flow inspectors.** Per-environment OIDC and SAML inspectors keep the
  last ten flows, including decoded claims, the raw ID token, and the
  base64 `SAMLResponse` exactly as posted, plus a per-hop activity log
  that records failures too. The OIDC inspector also lists live IdP
  sessions and can end them.
- **Traffic view.** Request/response transcripts of every OIDC and SAML
  exchange, including the back-channel logout requests scimtest sends,
  recorded by default into a bounded in-memory ring, with
  optional raw-secret capture. `--debug` additionally prints transcripts
  to stdout.
- **Fault Injection.** Choose **Fault Injection** in an environment's sidebar to
  arm a preset such as a temporary token outage, a slow token endpoint, an
  expired token, a broken signature, an unsigned token, a wrong audience, a
  missing claim, a replayed SAML assertion, or a SAML failure. The page waits
  for RP-initiated and SP-initiated flows, records each injection, and
  disarms active scenarios after 15 minutes. Token endpoint presets hit both
  code exchanges and refresh requests, and each injection names the grant. Inspector controls still provide
  one-shot clock skew, token and assertion lifetime, claim, signature, and
  error faults, plus tamper faults that break one validation rule in an
  otherwise valid response. OIDC tamper faults cover a wrong issuer or
  audience, an unknown signing key ID, an unsigned `alg: none` token, and a
  nonce mismatch. SAML tamper faults cover a wrong issuer, audience,
  destination, or recipient, an `InResponseTo` mismatch, and a replayed
  assertion ID. Logout token tamper faults cover an unsigned token, a wrong
  audience, a missing `events` claim, and a repeated `jti`. The same one-shot
  sign-in effects are available as `fault_*` URL parameters, such as
  `fault_tamper=wrong_issuer,alg_none`.
- **SCIM sync.** Push the directory to your app's SCIM endpoint, reconcile
  drift, import an existing remote directory with a preview, and inspect
  every request in the sync trace and per-resource history.
- **Config export.** Download SAML IDP metadata and the signing
  certificate as files, or fetch `GET /apps/{id}/config.json` for a
  machine-readable connection bundle to use in CI.
- **Backups.** Download and restore per-environment state snapshots.
  Backups contain credentials and signing keys; store them securely.

## IDP endpoints

Each environment can expose OIDC, SAML, or both, under its endpoint name
(slug):

- OIDC discovery: `/oidc/{slug}/.well-known/openid-configuration`
  (the RFC 8414 path-insertion form
  `/.well-known/openid-configuration/oidc/{slug}` also resolves)
- OIDC authorize: `/oidc/{slug}/authorize`
- OIDC token: `/oidc/{slug}/token`
- OIDC userinfo: `/oidc/{slug}/userinfo`
- OIDC end session (RP-initiated logout): `/oidc/{slug}/logout`
- OIDC JWKS: `/oidc/{slug}/jwks`
- SAML metadata: `/saml/{slug}/metadata` (`?download=1` for a file)
- SAML certificate: `/saml/{slug}/certificate.pem`
- SAML SSO: `/saml/{slug}/sso`

The OIDC flow signs RS256 ID tokens. SAML responses include a signed
assertion. Signing material is generated on first run and stored in the
SQLite state database.

Add `offline_access` to the OIDC scope to receive a refresh token. Each
refresh rotates the token: the response carries a replacement, and the
presented token stops working. A refresh can narrow the scope but not widen
it. It fails with `invalid_grant` once the user is deactivated or deleted.
The OIDC inspector lists users with live tokens and can revoke one user's
tokens or all of them, as an administrator would. Refresh tokens last 24
hours and are kept in memory, so restarting scimtest revokes them.

The chooser's **Sign-in method** sets how the user authenticated: **Password**
or **Password + MFA**. ID tokens report the method in `acr`, `amr`, and
`auth_time`. SAML assertions report it in `AuthnContextClassRef` and
`AuthnInstant`. When an app's `acr_values` or `RequestedAuthnContext` names a
recognized value, the chooser preselects the matching method and the response
echoes that value. Password matches the OASIS `PasswordProtectedTransport` and
`Password` classes and REFEDS SFA. Password + MFA matches REFEDS MFA, OpenID
PAPE `multi-factor`, and Microsoft `multipleauthn`. Discovery lists these
values in `acr_values_supported`. Other values leave Password selected.

Each sign-in starts or joins an IdP session for that browser and environment.
OIDC and SAML sign-ins from the same browser share the session, and ID tokens
carry its ID in `sid`. Signing in again as the same user keeps the session;
signing in as another user ends it and starts a new one. The chooser's
**Reuse session** button answers with the session's original user, method,
and time, so the app receives an older `auth_time` or `AuthnInstant`.
`prompt=login`, `max_age=0`, and SAML `ForceAuthn` hide the button and require
a fresh sign-in. So does a `max_age` shorter than the session's age. With
`prompt=none`, authorize skips the chooser and answers from the session. If
there is none, or it is older than `max_age`, authorize redirects with
`login_required`. A refreshed ID token keeps the original `auth_time`, `acr`,
`amr`, and `sid`.

A session ends when the app sends the browser to the end session endpoint,
when the tester ends it in the OIDC inspector, or when its user is
deactivated or deleted. The endpoint implements OpenID Connect RP-Initiated
Logout 1.0: it accepts `id_token_hint`, `client_id`, `post_logout_redirect_uri`,
and `state` by GET or POST. The hint must be an ID token this environment
issued to the app; an expired one is accepted. The `post_logout_redirect_uri`
must be one of the environment's registered redirect URIs and needs a hint or
`client_id`. scimtest ends the session that the hint's `sid` names, or the
browser's session when the hint has no `sid`, then redirects to
`post_logout_redirect_uri` with `state`. Without a hint for the browser's own
session, it asks the user to confirm first. Invalid requests show an error and never redirect.
Ending a session does not revoke tokens. Sessions last 30 days after their
latest sign-in and are kept in memory, so restarting scimtest ends them.

Set a **Back-channel logout URI** in OIDC setup to test OpenID Connect
Back-Channel Logout 1.0. When a session that issued ID tokens ends, for any of
the reasons above, scimtest POSTs a signed `logout_token` to that URI. The
token is typed `logout+jwt` and carries `iss`, `aud`, `iat`, `exp`, `jti`,
`sub`, and the back-channel logout `events` claim, and never a `nonce`. With
**Session required** (`backchannel_logout_session_required`), it also carries
the session's `sid`; without it, the app should end every session for `sub`.
Discovery advertises `backchannel_logout_supported` and
`backchannel_logout_session_supported`. scimtest sends the request in the
background with a 5-second timeout and does not follow redirects, so ending a
session never waits for the app. The URI must be reachable from the machine
that runs scimtest; no tunnel route is involved. The OIDC inspector's Recent
activity and the Traffic view record each request and the app's response.

Arm logout token faults from the inspector's **Simulate a failure** panel or
the API's `PUT /faults`. `logout_alg_none` sends an unsigned `alg: none`
token, `logout_wrong_audience` changes `aud`, `logout_missing_events` drops
`events`, and `logout_repeated_jti` delivers the same token, with the same
`jti`, a second time. Sign-ins leave these faults armed, and the next logout
token consumes them. A safe app answers each tampered token with `400 Bad
Request` and keeps the user's session. Recent activity marks a tampered token
that the app accepted with a 2xx status as failed.

Paste the service provider's RSA encryption certificate into SAML setup to
wrap that signed assertion in `EncryptedAssertion` (AES-128-GCM, AES-192-GCM,
or AES-256-GCM, RSA-OAEP). AES-256-GCM is the default.
Leave the field empty to post the signed assertion in the clear. The SAML
inspector still shows the signed assertion this IDP produced.

To require signed AuthnRequests, paste the service provider's RSA X.509
certificate into the request-signing certificate field. Leave the field empty
to accept unsigned AuthnRequests. scimtest validates HTTP-Redirect query
signatures and enveloped HTTP-POST XML signatures with SHA-256, SHA-384, or
SHA-512. When a certificate is present, scimtest rejects unsigned requests,
SHA-1 signatures, and signatures from any other certificate.

## Configuration

**Ports.** scimtest binds `127.0.0.1` and prefers, in order: `--port`,
`SCIMTEST_PORT`, the deprecated `PORT`, the port bound on the previous run
(so issuer URLs stay stable across restarts), and 8080 with fallback to a
nearby free port. `--port` and the environment variables pin the exact
port; startup fails if it cannot be bound.

**State.** State lives at the OS user config path under
`scimtest/state.db`. Use `--state-file` (or `SCIMTEST_STATE_FILE`) for an
isolated state file — also how you run a second instance next to a running
one, since only one process runs per state file; launching `scimtest`
again just opens the existing admin UI. Before schema migrations, a copy
of the database is written to a `backups/` directory next to it.

**Source-only browser runner.** `go run ./cmd/scimtest --help` lists the
development CLI flags. Use `--no-open` to start without opening a browser and
`--debug` to print redacted OIDC and SAML interactions to stdout
(`--debug-secrets` includes raw credentials; its output is sensitive). This
runner is not included in tagged releases.

**IDP base URL and tunnel.** Leave the IDP base URL empty when clients can
reach the current request host; set it when clients need another
externally reachable URL. Release builds automatically establish an
installation-authenticated tunnel through `https://scimtest.rselbach.com`:
no token or tunnel name is needed, a random tunnel path is assigned and
reused, and only the OIDC and SAML endpoints are exposed through it — the
admin UI and SCIM credentials stay on the loopback listener. The config
modal shows the tunnel state and an authorization link on first use (then
connected, connecting, failed with a retry button, or unavailable in source
builds). Unless `--no-open` is set, the GitHub authorization page opens
automatically. Compare the verification code shown in scimtest with the code on
the authorization page before continuing to GitHub.

## Release builds

Release builds require the `SCIMTEST_APPLICATION_PROFILE_ID` GitHub
Actions variable. They contain no tunnel enrollment private key; a new
installation authorizes its generated installation key through GitHub on its
first connection.

The macOS release also requires the Apple signing credentials documented in
[docs/desktop.md](docs/desktop.md). The release workflow signs and notarizes the
Apple silicon app and DMG. Native Ubuntu 24.04, Fedora 44, and Arch jobs build,
install, and test each Linux package. GoReleaser continues to publish
`scimtest-server`; it no longer builds the CLI application.

The tunnel server's application profile must allow these routes:

```text
GET /oidc/{slug}/.well-known/openid-configuration
GET /.well-known/openid-configuration/oidc/{slug}
GET /oidc/{slug}/jwks
GET,POST /oidc/{slug}/authorize
POST /oidc/{slug}/token
GET,POST /oidc/{slug}/userinfo
GET,POST /oidc/{slug}/logout
GET /saml/{slug}/metadata
GET /saml/{slug}/certificate.pem
GET,POST /saml/{slug}/sso
```

Tunnel startup diagnostics are written to the application log; private keys
are never logged. `automatic tunnel disabled: build has no application
profile` means the binary was built without the release profile linker value.

## Tunnel server

The companion `scimtest-server` (the public tunnel server) is documented
in [docs/server.md](docs/server.md). Regular scimtest users never need to
run it.
