# Local API reference

The local HTTP listener exposes the control API under `/api/v1`. The source
runner and desktop app use the same API. The public tunnel exposes only IDP
protocol endpoints.

## Connection and authentication

The instance lock file, `<state-file>.lock`, is a JSON object with `url` and
`token`. The URL identifies the active listener. Every API request requires
`X-Scimtest-Instance-Token: <token>`. The token changes when the process restarts.
The API rejects missing or incorrect tokens and does not authenticate through
browser cookies.

The listener requires the exact host from `url` and rejects cross-origin
browser mutations. Desktop builds retain the GitHub account gate. Status,
account, and tunnel controls remain available to authenticated local clients
while the desktop app is locked.

## Requests and responses

- Request bodies are JSON objects with `Content-Type: application/json`, up
  to 25 MiB. Commands without fields accept `{}` or no body.
- `PATCH` preserves omitted fields. Explicit `false`, empty strings, and empty
  arrays update their fields, subject to validation and the credential rules
  below. Unknown fields, `null`, and invalid field types are errors. Restore
  accepts the `null` values present in an exported backup.
- Environment, user, and group creation returns `201` and the resource object,
  including its generated `id`. Reads and updates return resource objects.
  List operations return arrays.
- Commands return JSON results, except clearing traffic and disarming faults,
  which return `204` with no body. Errors contain an `error` string and an HTTP
  error status. API responses do not require redirects or flash cookies.
- Environment IDs in paths select the target. UI selection cookies and
  `environment` or `app` query parameters cannot select a different environment.
- Environment configuration and connection exports include credentials.
  Backups also contain signing material. Responses are not cacheable.

`GET /api/v1` returns the operation catalog, including methods, paths, and
accepted body fields. The paths below are relative to `/api/v1`.

## Instance controls

| Method | Path | Result |
| --- | --- | --- |
| GET | `/status` | Readiness, desktop lock state, environment count, traffic and tunnel status. |
| GET, PATCH | `/config` | Global IDP URL, forwarded-header handling, and runtime debug settings. |
| GET | `/tunnel` | Tunnel state and enrollment details. |
| POST | `/tunnel/retry` | Retry the automatic tunnel connection. |
| GET | `/account` | Desktop GitHub account state. |
| POST | `/account/start`, `/account/retry`, `/account/logout` | Start, retry, or sign out of desktop authorization. |
| GET | `/traffic` | Recorded OIDC and SAML transcripts, including back-channel logout requests and SAML Single Logout messages. |
| PATCH | `/traffic/settings` | Set `record` and `record_secrets` booleans. |
| DELETE | `/traffic` | Clear recorded transcripts. |

GitHub authorization still requires approval through GitHub. The API exposes
the enrollment state so an agent can report that step to the user.

## Environment configuration

| Method | Path | Result |
| --- | --- | --- |
| GET, POST | `/environments` | List environments or create one. |
| GET, PATCH, DELETE | `/environments/{id}` | Read, update, or delete an environment. |
| GET | `/environments/{id}/connection` | OIDC connection values and SAML metadata/certificate values. |
| POST | `/environments/{id}/scim/test` | Test configured SCIM credentials and capabilities. |
| POST | `/environments/{id}/scim/discover` | Discover and save SCIM capabilities. |

Environment write fields are grouped below. Their complete names also appear
in the operation catalog.

- Identity uses `name` and `slug`.
- Protocol switches use `oidc_enabled`, `saml_enabled`, and `scim_enabled`.
- OIDC uses `oidc_client_id`, `oidc_client_secret`, `oidc_public_client`,
  `oidc_redirect_uris`, `allow_any_oidc_redirect`, `oidc_jwt_access_tokens`,
  `oidc_access_token_audience`, `oidc_backchannel_logout_uri`,
  `oidc_backchannel_logout_session_required`, and `regenerate_oidc_secret`. Redirect URIs
  are an array of strings. `oidc_jwt_access_tokens: true` issues RFC 9068 JWT
  access tokens whose `aud` is `oidc_access_token_audience`, or the client ID
  when the audience is empty.
  The back-channel logout URI must be an absolute HTTP(S) URL without a fragment.
- SAML uses `saml_entity_id`, `saml_acs_url`, `saml_slo_url`, `saml_audience`,
  `saml_name_id_field`, `saml_email_attribute_name`,
  `saml_request_certificate_pem`, `saml_encryption_certificate_pem`,
  `saml_encryption_algorithm`, and `saml_signing_mode`. The signing mode is
  `assertion` (the default), `response`, or `both`.
  `saml_slo_url` is the SP's Single Logout URL and must be an absolute HTTP(S) URL without a fragment.
- Directory claims use `include_groups_claim`, `chooser_mode`,
  `oidc_claim_mappings`, and `saml_attribute_mappings`. Claim mappings are
  objects whose keys are directory field names and whose values are claim or
  attribute names.
- SCIM uses `scim_base_url`, `scim_bearer_token`, and `scim_auto_open_trace`.
- Provider personas use `persona` (`generic`, `entra`, `okta`, or `google`)
  and `groups_overage_threshold`, the Entra ID group count above which tokens
  carry the groups overage form. `0` uses Entra ID's default of 200.

`regenerate_oidc_secret: true` generates a new confidential-client secret.
An empty `oidc_client_secret` preserves an existing secret or generates one
for a new confidential client. An empty `scim_bearer_token` clears it.
Public OIDC clients use PKCE and have no client secret. Disabling a protocol
removes its settings using the same rules as the web UI.

Claim-mapping objects replace the supplied mapping as a whole; omitted keys
within them receive the application's defaults. Omitting the mapping object
preserves all current mappings.

## Directory operations

All paths in this section are relative to `/environments/{id}`.

| Method | Path | Result |
| --- | --- | --- |
| GET, POST | `/users`, `/groups` | List or create resources. |
| GET, PATCH, DELETE | `/users/{user_id}`, `/groups/{group_id}` | Read, update, or delete a resource. |
| POST | `/users/{user_id}/restore`, `/groups/{group_id}/restore` | Restore a resource pending deletion. |
| POST | `/users/{user_id}/push`, `/groups/{group_id}/push` | Start SCIM sync for that resource. |
| GET | `/users/{user_id}/operations`, `/groups/{group_id}/operations` | Local and remote operation history. |
| POST | `/users/bulk-delete`, `/groups/bulk-delete` | Delete the resources named by the `ids` array. |

User writes accept `given_name`, `family_name`, `email`, `username`, and
`active`. New users default to active. An empty username uses the email.
They also accept the enterprise fields `employee_number`, `cost_center`,
`organization`, `division`, `department`, and `manager_id`, which names
another user in the same environment. An empty `manager_id` removes the
manager. `attributes` is an object of custom string attributes, such as
`{"role":"student"}`, and replaces every existing custom attribute. Send `{}`
to remove them all. Names start with a letter or underscore and use letters,
digits, and `_ . : / # -`. Protocol claim names such as `sub` and `iss`, and the
enterprise names such as `department`, are reserved. A user can have up to 50
custom attributes, and each value is one line of at most 1024 characters.
Group writes accept `display_name` and a `member_ids` array of local user IDs.
An empty array removes all group members.

With SCIM enabled, deletion marks a resource for remote deletion. Without
SCIM, deletion removes the local resource. Sync status and remote IDs are
managed by the application rather than writable request fields.

Bulk operations use `POST /tools/{action}`:

| Action | Body | Effect |
| --- | --- | --- |
| `seed-sample` | `{}` | Add the Greendale sample directory. |
| `create-users` | `{"count":10,"email_domain":"greendale.edu"}` | Generate users. |
| `activate-all`, `deactivate-all` | `{}` | Set all live users' active state. |
| `delete-all` | `{}` | Delete all users using the environment's deletion rules. |
| `clear-local` | `{}` | Clear the local users, groups, history, and sync state. |

## SCIM jobs and state

All paths in this section are relative to `/environments/{id}`.

| Method | Path | Result |
| --- | --- | --- |
| GET | `/sync/plan` | Pending SCIM operations. |
| POST | `/sync/start`, `/sync/reconcile` | Start a background job and return `202`. |
| GET | `/sync/status` | Current job, progress, events, completion, and errors. |
| POST | `/sync/cancel` | Request cancellation of the current job. |
| GET | `/sync/trace` | Last SCIM request/response trace. |
| POST | `/sync/reset` | Reset remembered remote sync state. |
| POST, GET | `/import/preview` | Fetch a remote directory preview or read the cached preview. |
| POST | `/import/apply` | Apply the cached preview and create a safety backup. |
| GET | `/backup` | Download an environment snapshot. |
| POST | `/restore` | Restore a snapshot supplied directly as the JSON body. |

The sync status response uses `running`, `done`, `success`, `error`, and
`events`. Poll until `done` is true, then check `success`. `after` selects
events after a sequence number. The application permits one SCIM job at a
time. Conflicting mutations return `409` while that job runs.

An import preview lasts ten minutes. A changed directory invalidates the
preview; applying it returns `409` and requires another preview. Each
environment has one cached preview. Restore requires a backup for the target
environment and saves a safety copy before replacing state.

## Protocol flows and diagnostics

All paths in this section are relative to `/environments/{id}`.

| Method | Path | Result |
| --- | --- | --- |
| POST | `/oidc/authorize` | Authorize a directory user and return `code`, `redirect_uri`, and `state`. |
| POST | `/oidc/playground` | Run authorization, code exchange, and userinfo locally and return the results. |
| GET | `/oidc/tokens` | Users holding live access or refresh tokens, with counts. `client_credentials` tokens are not listed. |
| DELETE | `/oidc/tokens` | Revoke every token, including `client_credentials` tokens, or one user's with `?user_id=`. Returns `revoked`. |
| GET | `/sessions` | Live IdP sessions, newest sign-in first. |
| DELETE | `/sessions` | End every IdP session, or one with `?session_id=`. Returns `ended`. |
| POST | `/saml/sign-in` | Return `acs_url`, base64 `saml_response`, and `relay_state`. |
| POST | `/saml/logout` | End a session with a SAML sign-in and return the signed `LogoutRequest` to deliver to the SP. |
| GET | `/saml/logouts` | IdP-initiated `LogoutRequest`s, newest first, with the SP's answers. |
| GET | `/signing-keys` | Published signing keys, active key first. |
| POST | `/signing-keys/rotate` | Sign with a new key and keep the old key published for `grace_period`. |
| GET | `/inspections/oidc`, `/inspections/saml` | Recent protocol inspections. |
| GET | `/flows` | Recent flow activity, including failures. |
| GET, PUT, DELETE | `/faults` | Read, replace, or disarm one-shot faults. |
| GET | `/scenarios` | Available fault presets and the current run. |
| POST | `/scenarios/arm` | Arm `preset_id` with an optional `count`. |
| POST | `/scenarios/disarm` | Disarm the current run. |

OIDC authorization accepts `user_id` and standard authorization fields,
including `client_id`, `redirect_uri`, `scope`, `state`, `nonce`,
`acr_values`, and PKCE parameters. `authn_strength` sets the sign-in method to
`password` or `mfa`. Without it, the first recognized `acr_values` entry sets
the method, and `password` is the default. The ID token reports the method in
`acr` and `amr`. Each API call is a fresh sign-in, so `auth_time` is the time
of the call. Codes are redeemed at the standard `/oidc/{slug}/token` endpoint.
With `offline_access` in the scope, the token response includes a
`refresh_token`. Redeem it at the same endpoint with
`grant_type=refresh_token`. Each refresh returns a replacement and
invalidates the presented token. After a revocation, refreshes fail with
`invalid_grant` and userinfo calls fail with `invalid_token`.
Userinfo remains at `/oidc/{slug}/userinfo`. The
[automation example](automation.md) performs both requests.

The same token endpoint accepts `grant_type=client_credentials` from a
confidential client and returns only an access token. Apps can check and
revoke their own tokens at `/oidc/{slug}/introspect` (RFC 7662) and
`/oidc/{slug}/revoke` (RFC 7009), with the token endpoint's client
authentication and a form-encoded `token`. Revoking a refresh token also
revokes the access tokens from the same authorization. The connection export
lists both URLs as `introspection_url` and `revocation_url`.

API calls normally carry no browser cookie, so each OIDC authorization,
playground run, and SAML sign-in through the API starts its own IdP session. ID
tokens carry the session ID in `sid`, and refreshed ID tokens keep it. Each
session in `GET /sessions` has `session_id`, `user_id`, `user`,
`signed_in_at`, `authn_strength`, `protocols` (`oidc`, `saml`, or both), and
`started_at`. A session with a SAML sign-in also has `saml_session_index`,
the `SessionIndex` its assertions carry, and `saml_name_id`. Ending a session signs that browser out, as the end session
endpoint `/oidc/{slug}/logout` does, but leaves its tokens valid. Ending an
unknown `session_id` returns `404`. Deactivating or deleting a user ends that
user's sessions.

When the environment has `oidc_backchannel_logout_uri`, ending a session that
issued ID tokens, by any of these routes, also POSTs a logout token to that
URI in the background. The `DELETE` response does not wait for the app.
`GET /flows` and `GET /traffic` show each logout request and the app's
response.

`POST /saml/logout` starts IdP-initiated SAML Single Logout. It accepts
`session_id` and an optional `binding`, `redirect` (the default) or `post`.
The environment needs `saml_slo_url`. scimtest ends the session, then returns
`request_id`, `binding`, and `url`. For HTTP-Redirect, `url` is the SP's Single
Logout URL with the signed query; send a browser there. For HTTP-POST, `url`
is the form action and `form` holds the base64 `SAMLRequest` to post. The SP
answers at `/saml/{slug}/slo`. `GET /saml/logouts` lists each request with
`outcome` (`pending`, `ok`, or `failed`), the SP's `status`, and a `detail`.
An unknown `session_id` returns `404`. SP-initiated `LogoutRequest`s arrive at
`/saml/{slug}/slo` directly and appear in `GET /flows`.

The headless playground accepts `{"user_id":"..."}` and optional `faults`
using the fields below. It handles confidential-client authentication or
public-client PKCE. Its result includes `authorize_status`, `token_status`,
`token`, `id_token_header`, `id_token_claims`, `userinfo_status`, and `userinfo`.
With JWT access tokens, it also includes `access_token_header` and
`access_token_claims`.
With `"refresh": true`, it also requests `offline_access`, redeems the refresh
token once, and adds `refresh_status`, `refresh`, and
`refreshed_id_token_claims`.
Protocol failures appear in those statuses and an `error` field; the enclosing
API response remains `200` when the experiment itself ran successfully.

SAML sign-in accepts `user_id`, optional `relay_state`, optional
`authn_strength`, and optional base64 `saml_request`. Without
`authn_strength`, a recognized class in the request's `RequestedAuthnContext`
sets the method. The assertion's `AuthnContextClassRef` reports the method,
and its `AuthnInstant` is the time of the call. For a signed Redirect-binding
request, pass the original query
string as `redirect_query` instead of splitting its signed fields. This keeps
the exact encoding needed for signature validation. API URL query parameters
are not SAML signing inputs.

Each signing key has `kid`, `active`, `created_at`, `published_until`, and
`certificate_pem`. The shared key that every environment starts with has the
`kid` `scimtest-dev` and no `created_at`. Rotation accepts an optional
`grace_period` duration from `0s` to `168h`; the default is `24h`, and `0s`
removes the old key at once. It returns the new key list. Rotation changes
only the selected environment. Backups include the environment's keys.
Restoring a backup made before key rotation existed returns the environment
to the shared key.

In identifier chooser mode, use `login_identifier` instead of `user_id` for
OIDC authorization, the playground, and SAML sign-in.

Fault writes accept duration strings in `id_token_ttl`, `assertion_ttl`, and
`clock_skew`, a `break_signature` boolean that corrupts the ID token signature
or every SAML signature, a `drop_claims` string array,
`token_error`, `saml_status`, and a `tamper` string array. Tamper values for
both protocols are `wrong_issuer` and `wrong_audience`. OIDC adds
`unknown_kid`, `alg_none`, and `nonce_mismatch`. SAML adds
`wrong_destination`, `wrong_recipient`, `in_response_to_mismatch`, and
`replayed_assertion`, which reuses the newest assertion ID the environment
sent. Back-channel logout tokens have their own tamper values:
`logout_alg_none`, `logout_wrong_audience`, `logout_missing_events`, and
`logout_repeated_jti`. Sign-ins leave these armed, and the next logout token
consumes them. The headless playground rejects them. With JWT access tokens, tamper values, `break_signature`, and
`clock_skew` also apply to the access token. Invalid fault values are
rejected. Fault scenarios expire after
15 minutes. The `stale-jwks` scenario serves `count` JWKS responses without
the active signing key.

Traffic, inspections, flow activity, IdP sessions, faults, and jobs are in
memory. They disappear when the app restarts. Traffic retains 100 entries,
inspectors retain ten flows, and flow activity retains 20 events per
environment.

Diagnostics preserve their existing field names, including capitalized names
such as `Summary` and `CreatedAt` in operation history. Disabling traffic
recording also disables recording secrets.
