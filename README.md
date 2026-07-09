# scimtest

`scimtest` is a local web-only auth testing service. It combines:

- a SCIM sync control surface for local users and groups
- an OIDC authorization-code test IDP
- a SAML HTTP-POST test IDP

Users and groups are stored once in SQLite and are shared by SCIM sync, OIDC claims, and SAML attributes.

## Run

```sh
go run .
```

The admin server listens on `http://127.0.0.1:8080` by default. Set `PORT` to use a different port:

```sh
PORT=8090 go run .
```

State is stored at the OS user config path under `scimtest/state.db`. Set `SCIMTEST_STATE_FILE` to use an isolated SQLite state file.

## Config

The config modal has two base URLs:

- SCIM base URL: the remote SCIM server to sync to and import from
- IDP base URL: the issuer URL published in OIDC/SAML metadata

SCIM can be disabled from the config modal. When disabled, the users and groups pages hide SCIM sync actions, remote IDs, sync status, trace links, and sync errors; the local OIDC/SAML IDP continues to use the same users and groups.

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
