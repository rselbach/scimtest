# scimtest

`scimtest` is a local web-only auth testing service. It combines:

- a SCIM sync control surface for local users and groups
- an OIDC authorization-code test IDP
- a SAML HTTP-POST test IDP

Users and groups form one global directory stored in SQLite. Every app uses that
directory for OIDC claims, SAML attributes, and optional SCIM provisioning.
Each app has independent SCIM credentials, remote IDs, sync state, and errors.
Existing environment-based databases are flattened automatically; their apps and
directory entries are preserved, and environment SCIM settings move onto apps.

## Run

```sh
go run .
```

The admin server listens on `http://127.0.0.1:8080` by default. Set `PORT` to use a different port:

```sh
PORT=8090 go run .
```

State is stored at the OS user config path under `scimtest/state.db`. Set `SCIMTEST_STATE_FILE` to use an isolated SQLite state file.

Use `--debug` to log redacted OIDC and SAML interactions. Use
`--debug-secrets` only when raw credentials, tokens, and assertions are required;
its output is sensitive.

## Config

The global settings modal configures the IDP base URL published in OIDC/SAML
metadata and the optional rgrok tunnel.

Enable `Sync` on an app to configure its SCIM base URL and bearer token. The app
selector in the top bar chooses which server the sync, import, reset, remote ID,
status, trace, and error views refer to. Apps without Sync enabled still use the
global directory for OIDC and SAML.

Leave IDP base URL empty when clients can reach the current request host. Set it when clients need a public tunnel or another externally reachable URL.

The built-in rgrok tunnel exposes only the OIDC and SAML endpoints. The admin UI and its SCIM credentials remain available only on the loopback listener.

## IDP Endpoints

Each app can expose OIDC, SAML, or both:

- OIDC discovery: `/oidc/{slug}/.well-known/openid-configuration`
- OIDC authorize: `/oidc/{slug}/authorize`
- OIDC token: `/oidc/{slug}/token`
- OIDC userinfo: `/oidc/{slug}/userinfo`
- OIDC JWKS: `/oidc/{slug}/jwks`
- SAML metadata: `/saml/{slug}/metadata`
- SAML SSO: `/saml/{slug}/sso`

The OIDC flow signs RS256 ID tokens. SAML responses include a signed assertion. Signing material is generated on first run and stored in the SQLite state database.
