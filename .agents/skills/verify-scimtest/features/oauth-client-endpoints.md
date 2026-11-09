# Use the OAuth client endpoints

An app's backend can get a token for itself with `client_credentials`, check
any token through introspection, and revoke its own tokens. These are public
protocol endpoints, so the proof is real HTTP requests against them.

## Sub-features

- `client-credentials` issues an access token with no ID or refresh token to a
  confidential client and rejects public clients with `unauthorized_client`.
- `introspection` reports active user, refresh, and client tokens, and
  `active: false` for unknown, revoked, or deactivated-user tokens.
- `revocation` ends one access token, or a refresh token and every access
  token from the same authorization.
- `client-endpoint-auth` rejects wrong client credentials with
  `invalid_client`.
- `client-endpoint-discovery` advertises both endpoints and the grant type.

## How to get to it (user POV)

- Read `introspection_endpoint`, `revocation_endpoint`, and
  `grant_types_supported` from the environment's `Discovery JSON`.
- Read `token_url`, `introspection_url`, and `revocation_url` from
  `Download config JSON` in OIDC setup.
- POST form-encoded requests to those URLs with the client ID and secret, the
  way an app's backend or resource server would.

## Driving it with Browser

Preconditions:

- Greendale Portal has OIDC enabled as a confidential client with client ID
  `greendale-portal`.
- The Greendale sample is loaded.
- Doctor passes for the same run.

- **Find the endpoints.** Choose `Show options for Greendale Portal`, read the
  `Discovery JSON` href, and fetch it with curl. It lists
  `introspection_endpoint` and `revocation_endpoint` under the issuer, and
  `grant_types_supported` includes `client_credentials`. Fetch the config JSON
  as in the config export recipe and read the client secret from it.
- **Get a client token.** POST `grant_type=client_credentials&scope=courses.read`
  to the token URL with Basic authentication. Status is 200. The body has
  `access_token`, `token_type` `Bearer`, and `scope` `courses.read`, and no
  `id_token` or `refresh_token`. Userinfo with that token returns 401.
- **Introspect it.** POST `token=<client token>` to the introspection URL with
  the same authentication. The body has `active: true`, `sub` and `client_id`
  `greendale-portal`, and `scope` `courses.read`.
- **Get user tokens.** Run the API playground with `"refresh": true`, or an
  API authorization with `offline_access` redeemed at the token URL, to get an
  access token and a refresh token for Troy Barnes. Introspecting each shows
  `active: true` and `username` `tbarnes`.
- **Revoke the refresh token.** POST `token=<refresh token>` to the revocation
  URL. Status is 200 with an empty body. Introspecting the refresh token and
  Troy's access token now returns only `active: false`, and a refresh with the
  revoked token fails with `invalid_grant`.
- **Check the flow log.** The OIDC inspector's activity shows the
  `client_credentials` issue, each introspection, and the revocation.
- **Reject bad credentials.** Repeat an introspection with a wrong secret.
  Status is 401 with `invalid_client` and a `WWW-Authenticate` header.

## Gotchas

- Introspection and revocation take only POST with a form-encoded `token`.
- A public-client environment gets `unauthorized_client` for
  `client_credentials`, and discovery omits that grant type.
- Revoking an unknown token also returns 200. Prove a revocation by
  introspecting the token afterward, not by the status code.
- The inspector's `Active tokens` table counts only user tokens.
  `client_credentials` tokens appear in the flow log and introspection.
- Tokens and the client secret are live credentials for this run. Keep them in
  the ignored artifact directory and redact them from reports.
