# scimtest

`scimtest` is a local auth testing service: it plays the identity provider
(and SCIM client) so you can test your app's SAML, OIDC, and SCIM
implementations without touching a real IDP. It combines:

- an OIDC authorization-code test IDP
- a SAML HTTP-POST test IDP
- a SCIM sync control surface for local users and groups

Everything runs in a local web UI. Each environment owns its users and
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

- **Environments.** Each environment is one app you are testing, with its
  own directory, credentials, and protocol configuration. The environment
  selector in the top bar sets the context for the whole admin UI.
- **OIDC playground.** A built-in relying party that runs the full
  authorization-code exchange and shows the token response, decoded and
  raw ID token, and userinfo on one page.
- **Flow inspectors.** Per-environment OIDC and SAML inspectors keep the
  last ten flows, including decoded claims, the raw ID token, and the
  base64 `SAMLResponse` exactly as posted, plus a per-hop activity log
  that records failures too.
- **Traffic view.** Request/response transcripts of every OIDC and SAML
  exchange, recorded by default into a bounded in-memory ring, with
  optional raw-secret capture. `--debug` additionally prints transcripts
  to stdout.
- **Fault Injection.** Choose **Fault Injection** in an environment's sidebar to
  arm a preset such as a temporary token outage, a slow token endpoint, an
  expired token, a broken signature, a missing claim, or a SAML failure. The
  page waits for RP-initiated and SP-initiated flows, records each injection,
  and disarms active scenarios after 15 minutes. Inspector controls still
  provide one-shot clock skew, claim, signature, and error faults. The same
  one-shot effects are available as `fault_*` URL parameters.
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
- OIDC JWKS: `/oidc/{slug}/jwks`
- SAML metadata: `/saml/{slug}/metadata` (`?download=1` for a file)
- SAML certificate: `/saml/{slug}/certificate.pem`
- SAML SSO: `/saml/{slug}/sso`

The OIDC flow signs RS256 ID tokens. SAML responses include a signed
assertion. Signing material is generated on first run and stored in the
SQLite state database.

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
