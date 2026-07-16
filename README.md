# scimtest

`scimtest` is a local web-only auth testing service. It combines:

- a SCIM sync control surface for local users and groups
- an OIDC authorization-code test IDP
- a SAML HTTP-POST test IDP

Users and groups form one shared directory stored in SQLite. Every environment
uses that directory for OIDC claims, SAML attributes, and optional SCIM
provisioning. Each environment has independent SCIM credentials, remote IDs,
sync state, operation history, and errors.
Existing environment-based databases are flattened automatically; their apps and
directory entries are preserved, and environment SCIM settings move onto apps.

## Run

```sh
go run .
```

The admin server opens in your browser at `http://127.0.0.1:8080` by default. If
that port is occupied, it tries successively higher ports. Use `--port` (or the
`PORT` environment variable) to require a specific port from 1 through 65535
(startup fails if that port cannot be bound):

```sh
go run . --port 8090
```

Use `--no-open` to start the server without opening the admin UI in a browser.

Only one process runs for each state file. Launching `scimtest` again opens the
existing admin UI and exits; use a different `SCIMTEST_STATE_FILE` for an
independent instance.

State is stored at the OS user config path under `scimtest/state.db`. Set `SCIMTEST_STATE_FILE` to use an isolated SQLite state file.

Use `--debug` to log redacted OIDC and SAML interactions. Use
`--debug-secrets` only when raw credentials, tokens, and assertions are required;
its output is sensitive.

## Config

The global settings modal configures the IDP base URL published in OIDC/SAML
metadata. Release builds automatically establish an anonymous rgrok tunnel; no
token or tunnel name is required. A random tunnel name is assigned and reused
for the local installation when available.

The environment selector in the top bar sets the context for the whole admin UI.
Sync, import, reset, remote IDs, status, traces, and errors always refer to that
environment. Environments without Sync enabled still use the shared directory
for OIDC and SAML. Editing a shared user or group marks it dirty in every
SCIM-enabled environment.

Starting a sync opens a live details view with one row per SCIM operation. The
view can be closed without stopping the sync and reopened from the inline
progress bar. Raw requests and responses remain available in the sync trace.

Leave IDP base URL empty when clients can reach the current request host. Set it when clients need a public tunnel or another externally reachable URL.

The built-in rgrok tunnel exposes only the OIDC and SAML endpoints. The admin UI and its SCIM credentials remain available only on the loopback listener.

Release builds require the `RGROK_APPLICATION_PROFILE_ID` GitHub Actions
variable and `RGROK_APPLICATION_PRIVATE_SEED_BASE64` secret. The latter is the
standard base64 encoding of the raw 32-byte Ed25519 seed. Local source builds
omit the tunnel when no application identity is injected; tests generate their
own keys and do not read local key files.

Convert an unencrypted OpenSSH Ed25519 private key to the required secret value
from the repository root:

```sh
just rgrok-key /path/to/id_ed25519
```

## IDP Endpoints

Each environment can expose OIDC, SAML, or both:

- OIDC discovery: `/oidc/{slug}/.well-known/openid-configuration`
- OIDC authorize: `/oidc/{slug}/authorize`
- OIDC token: `/oidc/{slug}/token`
- OIDC userinfo: `/oidc/{slug}/userinfo`
- OIDC JWKS: `/oidc/{slug}/jwks`
- SAML metadata: `/saml/{slug}/metadata`
- SAML SSO: `/saml/{slug}/sso`

The OIDC flow signs RS256 ID tokens. SAML responses include a signed assertion. Signing material is generated on first run and stored in the SQLite state database.
