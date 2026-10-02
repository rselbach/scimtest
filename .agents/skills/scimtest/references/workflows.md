# scimtest workflows

All API paths here are relative to `/api/v1` unless an environment prefix is
stated. Substitute returned IDs; example names and URLs are disposable test
data. The catalog at `GET /` lists the running build's supported operations.

## Environment and directory setup

After checking `GET /environments`, create an OIDC environment if needed by
posting this body to `/environments`:

```json
{
  "name": "Greendale Portal",
  "slug": "greendale-portal",
  "oidc_enabled": true,
  "oidc_client_id": "greendale-client",
  "oidc_redirect_uris": ["http://127.0.0.1:9999/callback"],
  "include_groups_claim": true
}
```

Save the returned `id` as `ENV_ID`. For a real relying party, use its registered
redirect URI. Leave `allow_any_oidc_redirect` disabled unless unrestricted
redirects are part of the requested experiment. Read
`/environments/{ENV_ID}/connection` for the generated secret and endpoint URLs.

Environment writes use `oidc_enabled` and `saml_enabled`; readbacks summarize
those protocols in `protocol`. Use the catalog's write fields rather than
sending a complete readback object as an update.

Create Troy with `POST /environments/{ENV_ID}/users`:

```json
{"given_name":"Troy","family_name":"Barnes","email":"troy@greendale.edu","username":"tbarnes","active":true}
```

Save the returned `id` as `USER_ID`. Use local user IDs in a group's
`member_ids` array when posting to `/environments/{ENV_ID}/groups` with a
`display_name`. These are IDs within that environment, not remote SCIM IDs.
Use `PATCH` on an individual resource for edits. `{"member_ids":[]}` removes
all group memberships.

For a larger directory, `POST /environments/{ENV_ID}/tools/seed-sample` with
`{}` adds ten Greendale users and three groups. Repeating it adds no duplicate
sample records. One sample user is deliberately inactive. Read environment
`/users` and `/groups` afterward instead of assuming IDs or active states.

Environment `tools/create-users` accepts `count` and `email_domain`. The catalog
also offers activation, deletion, and local-clear actions. With SCIM configured,
deletion marks resources for the next sync; `POST /users/{id}/restore` or
`POST /groups/{id}/restore` under that environment undoes the mark. Without
SCIM, deletion removes the local record. Clearing local state does not delete
remote resources.

## OIDC

For a complete local experiment, call:

```sh
python3 "${SCIMTEST_API}" --state-file "${SCIMTEST_STATE}" \
  POST "/environments/${ENV_ID}/oidc/playground" \
  --json "{\"user_id\":\"${USER_ID}\"}"
```

Success includes `authorize_status: 302`, `token_status: 200`, and
`userinfo_status: 200`. Inspect `id_token_claims` and `userinfo` for the
requested identity and groups. The helper's exit status alone is insufficient.
Public clients are tested with PKCE; confidential clients use their secret.

For an application's real authorization-code flow, use its client ID,
registered redirect URI, scopes, state, nonce, and any PKCE challenge in
`POST /environments/{ENV_ID}/oidc/authorize`. Redeem the returned `code` at the
`token_url` from `/connection`, using form encoding and that client's
authentication or PKCE verifier. Read `userinfo_url` with the resulting
access token. The instance-token header belongs only on local API calls.

The connection export also contains `issuer`, `discovery_url`, `authorize_url`,
and `jwks_url`. Configure the relying party from these values. A manually
exchanged code does not prove the app's callback or login session; exercise
that path separately when it is the test's goal.

In `chooser_mode: "identifier"`, supply `login_identifier` instead of `user_id`
to authorization, playground, and SAML requests. Use an active user's username
or email.

To test an app's step-up check, set `authn_strength` to `mfa` or `password` in
the authorization or SAML sign-in request. The ID token reports the choice in
`acr` and `amr`. The SAML assertion reports it in `AuthnContextClassRef`. Each
API call is a fresh sign-in with its own IdP session. `prompt=none`, `max_age`,
session reuse, and the end session confirmation need a browser, because they
depend on the cookie that names the browser's IdP session.

To test an app's logout, read the ID token's `sid`, send the app's
RP-initiated logout to `/oidc/{slug}/logout`, and confirm the session is gone
from `GET /environments/{ENV_ID}/sessions`. `DELETE` on the same path with
`?session_id=` ends one session as an administrator would. Deactivating or
deleting the user also ends that user's sessions. None of these revoke tokens.

To test back-channel logout, set `oidc_backchannel_logout_uri` to the app's
logout endpoint, and `oidc_backchannel_logout_session_required: true` when the
app needs `sid`. The app must be reachable from the machine that runs
scimtest. Exchange a code first: only sessions that issued an ID token send a
logout token. Then end the session by any route above. Delivery is
asynchronous, so poll `GET /environments/{ENV_ID}/flows` for the
`backchannel-logout` stage, which records the app's status, and check that the
app ended its own session.

## SAML

Create or patch an environment with `saml_enabled: true`, `saml_entity_id`,
and `saml_acs_url` matching the service provider. Read the SAML connection
export for the IDP entity ID, SSO URL, metadata URL, and certificate. Metadata
and certificate requests use those exported protocol URLs.

`POST /environments/{ENV_ID}/saml/sign-in` accepts `user_id`, optional
`relay_state`, and optional base64 `saml_request`. It returns `acs_url`, base64
`saml_response`, and `relay_state`. Decode the response to inspect it. To test
the service provider, submit it to the ACS with form fields `SAMLResponse`
and `RelayState` and verify the service provider's resulting session.

For a signed Redirect-binding request, pass the original encoded query as
`redirect_query`. Do not combine it with separate `saml_request`, `sig_alg`,
`signature`, or `relay_state` fields. Re-encoding signed fields can invalidate
their signature. The API URL's query is not SAML signing input.

To test SAML Single Logout, set `saml_slo_url` to the service provider's
SingleLogoutService. scimtest's own endpoint is `/saml/{slug}/slo` (`slo_url`
in the connection export), and the metadata advertises it for HTTP-Redirect
and HTTP-POST. `GET /environments/{ENV_ID}/sessions` lists each SAML session's
`saml_session_index` and `saml_name_id`. For SP-initiated logout, have the SP
send its `LogoutRequest` through the browser, then confirm the session is gone
and read the `saml logout` row in `/flows`. A `failed` row names the error
status scimtest answered, such as a NameID or SessionIndex that does not match
the session. For IdP-initiated logout, `POST
/environments/{ENV_ID}/saml/logout` with `session_id` and optional `binding`
(`redirect` or `post`) ends the session and returns the signed message: send a
browser to `url` for Redirect, or post `form` to `url` for POST. The SP answers
at `/saml/{slug}/slo`, and `GET /environments/{ENV_ID}/saml/logouts` shows each
request's `outcome`. A pinned `saml_request_certificate_pem` also requires
signed logout messages. Ending a session any other way does not notify the SP.

## SCIM sync and import

Paths in this section follow `/environments/{ENV_ID}`. Set `scim_enabled`,
`scim_base_url`, and `scim_bearer_token` on the intended environment. A URL alone
is incomplete; adding the token completes setup. `POST /scim/test` tests the
target. `POST /scim/discover` also saves its capabilities.

1. Read `/sync/plan` and compare its operations with the user's requested
   changes. Confirm that the environment points to the authorized SCIM target.
2. Start `/sync/start` with `POST {}`, or use a user's or group's `/push`
   endpoint for that resource. A `202` response is job acceptance.
3. Poll `GET /sync/status` until `done`. Inspect `success`, `error`, and
   `events`; `?after=N` limits events by sequence number. Wait briefly between
   polls and bound the wait. `/sync/cancel` requests cancellation.
4. Check persisted remote IDs and the target's actual resource state.
   `/sync/trace` and `/users/{id}/operations` or `/groups/{id}/operations`
   explain remote requests and errors.

`POST /sync/reconcile` also starts a job and can write remote changes.
`POST /sync/reset` forgets remembered sync state; it is not a remote rollback.
The app permits one SCIM job at a time. Conflicting state changes return `409`.

To import the target directory, `POST /import/preview`, inspect the counts and
status, then `POST /import/apply` within the requested scope. A preview expires
after ten minutes, and a changed baseline requires a fresh preview. Applying
creates a safety backup before replacing local state.

## Backups

Save `GET /environments/{ENV_ID}/backup` with restrictive permissions:

```sh
umask 077
python3 "${SCIMTEST_API}" --state-file "${SCIMTEST_STATE}" \
  GET "/environments/${ENV_ID}/backup" > "${BACKUP_PATH}"
```

Check the command succeeded before treating the file as a backup. Restore
with the exported JSON itself:

```sh
python3 "${SCIMTEST_API}" --state-file "${SCIMTEST_STATE}" \
  POST "/environments/${ENV_ID}/restore" --data-file "${BACKUP_PATH}"
```

Restore requires the matching target environment and saves a safety copy.
It replaces local state and does not undo prior remote SCIM writes.

## Lifecycle scenarios

Paths in this section follow `/environments/{ENV_ID}`. A scenario changes the
directory, then sends the messages the change calls for in every protocol the
environment uses, and records the app's answers. `POST /lifecycle/joiner`
takes user fields and optional `group_ids`. `POST /lifecycle/mover` takes
`user_id`, `add_group_ids`, and `remove_group_ids`. `POST /lifecycle/leaver`
takes `user_id`. Each returns `202` and the run. These scenarios write to the
directory, and their SCIM pushes write to the configured target, so keep them
within the user's authorized environment.

Poll `GET /lifecycle/{RUN_ID}` until no step is `running`. Read each step's
`status`, `detail`, and `messages`. A `skipped` step names the setup it lacks.
A leaver's SAML Single Logout step is `needs_browser` with a `browser_url`:
open it in a browser and choose **Send LogoutRequest**. The step then waits
for the SP's `LogoutResponse`. A mover's `oidc-groups` and `saml-groups`
steps stay `waiting` until the app signs the user in or refreshes again. Run a
real sign-in through the app, then read the step to see the groups the token
or assertion carried. Check the app's own state too: the provisioned or
deactivated resource, its ended session, and its rejected tokens.

## Faults and diagnostics

Use the playground's `faults` object for one OIDC experiment:

```json
{"user_id":"RETURNED_USER_ID","faults":{"token_error":"invalid_grant"}}
```

This experiment should report `token_status: 400` and a token error even though
the API call itself returns `200`. Other fault fields include duration strings
`id_token_ttl`, `assertion_ttl`, and `clock_skew`, boolean `break_signature`,
array `drop_claims`, `saml_status`, and array `tamper`. SAML status and
assertion TTL faults apply to SAML flows. Tamper values break one check in an
otherwise valid response. `wrong_issuer` and `wrong_audience` apply to both
protocols. OIDC adds `unknown_kid`, `alg_none`, and `nonce_mismatch`. SAML
adds `wrong_destination`, `wrong_recipient`, `in_response_to_mismatch`, and
`replayed_assertion`. Replay needs an earlier SAML sign-in in the same
environment. Logout token tamper values `logout_alg_none`,
`logout_wrong_audience`, `logout_missing_events`, and `logout_repeated_jti`
apply only through `PUT /faults`: sign-ins leave them armed, and the next
back-channel logout token consumes them. A safe app answers `400`.

To affect the next incoming protocol flow, `PUT /environments/{ENV_ID}/faults`.
Read or disarm it with `GET` or `DELETE` on the same path. Disarming returns
an empty `204`. A one-shot fault can be consumed by another incoming flow, so
keep fault experiments in their intended environment.

For repeated faults, read `/environments/{ENV_ID}/scenarios` for available
presets, then `POST /scenarios/arm` under the same environment with `preset_id`
and an optional integer `count`. Inspect the returned run and disarm with
`POST /scenarios/disarm`. These scenarios expire after fifteen minutes.

To test refresh handling, include `offline_access` in the OIDC scope and redeem
the returned `refresh_token` with `grant_type=refresh_token`. Each refresh
rotates the token. The playground's `"refresh": true` option runs one refresh
for you and returns `refresh_status`, `refresh`, and
`refreshed_id_token_claims`. `GET /environments/{ENV_ID}/oidc/tokens` lists users with
live tokens. `DELETE` on the same path revokes them all, or one user's with
`?user_id=`, so the next refresh fails with `invalid_grant`.

Use environment `/flows` and `/inspections/oidc` or `/inspections/saml` for
protocol outcomes. `/traffic` is global; `PATCH /traffic/settings` accepts
`record` and `record_secrets`. Keep secret recording off unless the specific
test needs it. `DELETE /traffic` clears transcripts and returns `204`.
History fields can use capitalized keys such as `Summary` and `CreatedAt`.

## Desktop account and tunnel

Read `/status`, `/account`, and `/tunnel` before troubleshooting desktop
access. They remain available to an authenticated API client while the
desktop account gate is locked. `/account` reports enrollment details when
GitHub authorization is required. Present the enrollment URL to the user;
local API access does not complete their GitHub approval.

`POST /account/start` returns the authorization state; it does not open a
browser. `/account/retry` and `/tunnel/retry` retry connection setup.
Use `/account/logout` only when signing out is the intended action. A source
build without a release identity cannot provide a public tunnel.
