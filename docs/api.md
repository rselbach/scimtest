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
| GET | `/traffic` | Recorded OIDC and SAML transcripts. |
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
  `oidc_redirect_uris`, `allow_any_oidc_redirect`, and
  `regenerate_oidc_secret`. Redirect URIs are an array of strings.
- SAML uses `saml_entity_id`, `saml_acs_url`, `saml_audience`,
  `saml_name_id_field`, `saml_email_attribute_name`,
  `saml_request_certificate_pem`, `saml_encryption_certificate_pem`, and
  `saml_encryption_algorithm`.
- Directory claims use `include_groups_claim`, `chooser_mode`,
  `oidc_claim_mappings`, and `saml_attribute_mappings`. Claim mappings are
  objects whose keys are directory field names and whose values are claim or
  attribute names.
- SCIM uses `scim_base_url`, `scim_bearer_token`, and `scim_auto_open_trace`.

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
| POST | `/saml/sign-in` | Return `acs_url`, base64 `saml_response`, and `relay_state`. |
| GET | `/inspections/oidc`, `/inspections/saml` | Recent protocol inspections. |
| GET | `/flows` | Recent flow activity, including failures. |
| GET, PUT, DELETE | `/faults` | Read, replace, or disarm one-shot faults. |
| GET | `/scenarios` | Available fault presets and the current run. |
| POST | `/scenarios/arm` | Arm `preset_id` with an optional `count`. |
| POST | `/scenarios/disarm` | Disarm the current run. |

OIDC authorization accepts `user_id` and standard authorization fields,
including `client_id`, `redirect_uri`, `scope`, `state`, `nonce`, and PKCE
parameters. Codes are redeemed at the standard `/oidc/{slug}/token` endpoint.
With `offline_access` in the scope, the token response includes a
`refresh_token`. Redeem it at the same endpoint with
`grant_type=refresh_token`. Each refresh returns a replacement and
invalidates the presented token.
Userinfo remains at `/oidc/{slug}/userinfo`. The
[automation example](automation.md) performs both requests.

The headless playground accepts `{"user_id":"..."}` and optional `faults`
using the fields below. It handles confidential-client authentication or
public-client PKCE. Its result includes `authorize_status`, `token_status`,
`token`, `id_token_header`, `id_token_claims`, `userinfo_status`, and `userinfo`.
Protocol failures appear in those statuses and an `error` field; the enclosing
API response remains `200` when the experiment itself ran successfully.

SAML sign-in accepts `user_id`, optional `relay_state`, and optional base64
`saml_request`. For a signed Redirect-binding request, pass the original query
string as `redirect_query` instead of splitting its signed fields. This keeps
the exact encoding needed for signature validation. API URL query parameters
are not SAML signing inputs.

In identifier chooser mode, use `login_identifier` instead of `user_id` for
OIDC authorization, the playground, and SAML sign-in.

Fault writes accept duration strings in `id_token_ttl`, `assertion_ttl`, and
`clock_skew`, a `break_signature` boolean, a `drop_claims` string array,
`token_error`, `saml_status`, and a `tamper` string array. Tamper values for
both protocols are `wrong_issuer` and `wrong_audience`. OIDC adds
`unknown_kid`, `alg_none`, and `nonce_mismatch`. SAML adds
`wrong_destination`, `wrong_recipient`, `in_response_to_mismatch`, and
`replayed_assertion`, which reuses the newest assertion ID the environment
sent. Invalid fault values are rejected. Fault scenarios expire after
15 minutes.

Traffic, inspections, flow activity, faults, and jobs are in memory. They
disappear when the app restarts. Traffic retains 100 entries, inspectors retain
ten flows, and flow activity retains 20 events per environment.

Diagnostics preserve their existing field names, including capitalized names
such as `Summary` and `CreatedAt` in operation history. Disabling traffic
recording also disables recording secrets.
