# Choose a provider persona

The environment dialog's Provider persona shapes OIDC claims like Microsoft
Entra ID, Okta, or Google. The Entra ID persona also adds groups overage and
switches SCIM sync to Entra ID's dialect.

## Sub-features

- `persona-setting` saves the persona and the Entra ID groups overage
  threshold.
- `persona-claims` shows each persona's claims in the ID token and userinfo.
- `persona-overage` replaces `groups` with `_claim_names` and
  `_claim_sources`, and serves the groups from the source endpoint.
- `persona-entra-scim` sends externalId filter lookups and capitalized PATCH
  operations during sync.

## How to get to it (user POV)

- Choose `Manage` next to the active environment, then edit the environment.
  The Environment step of dialog `Set up environment` has `Provider persona`
  and `Entra ID groups overage threshold`.
- Agents can set `persona` and `groups_overage_threshold` with
  `PATCH /api/v1/environments/{id}`.

## Driving it with Browser

Preconditions:

- Greendale Portal has OIDC enabled with groups in sign-in responses.
- The Greendale sample is loaded.
- For `persona-entra-scim`, SCIM points at a local SCIM target that records
  requests.

- **Open the setting.** Open dialog `Set up environment` for Greendale Portal.
  Combobox `Provider persona` shows `Generic` selected, and spinbutton
  `Entra ID groups overage threshold` is empty with placeholder `200`.
  Capture this state.
- **Save Entra ID.** Choose `Microsoft Entra ID`, enter `1` as the threshold,
  and choose `Save environment`. Expect status `environment updated`.
- **Confirm persistence.** Reload and reopen the dialog. `Microsoft Entra ID`
  is selected and the threshold is `1`.
- **Check claims.** Run the OIDC playground as Jeff Winger, who is in one
  group. `id_token_claims` include `tid`, `oid`, `upn`
  `jwinger@greendale.edu`, `preferred_username` `jwinger@greendale.edu`, and
  `groups`, with no `email_verified`. Run it as Troy Barnes, who is in two
  groups. The claims have `_claim_names` and `_claim_sources` instead of
  `groups`.
- **Call the overage endpoint.** `POST` the `_claim_sources` endpoint with
  Troy's access token as a bearer token and `{"securityEnabledOnly":false}`.
  The response's `value` lists Troy's two groups. Another user's token gets
  `403` with `Authorization_RequestDenied`.
- **Check the SCIM dialect.** Sync, deactivate a synced user, and sync again.
  The target receives `GET /Users?filter=externalId eq "..."` with no `count`,
  then a `PATCH` whose only operation is
  `{"op":"Replace","path":"active","value":"False"}`.
- **Try the other personas.** Switch to `Okta` and run the playground: claims
  have `ver: 1` and `groups` starting with `Everyone`. Switch to `Google`:
  claims have `hd: greendale.edu` and `email_verified: true`.

## Gotchas

- `tid` and `oid` derive from the environment and user IDs. A copied or newly
  created environment gets new values.
- The overage endpoint answers `404` unless the persona is Entra ID.
- Personas do not change SAML assertions.
- A threshold of `0` or an empty field uses Entra ID's default of 200, so the
  Greendale sample never triggers overage without a smaller threshold.
