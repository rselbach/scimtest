# Run lifecycle scenarios

The Lifecycle tab runs a joiner, mover, or leaver across SCIM, OIDC, and SAML
in one action. Each run keeps a checklist of what scimtest sent, where, and
how the app answered.

## Sub-features

- `lifecycle-joiner` creates a user, adds them to groups, and pushes the user
  and then each group through SCIM.
- `lifecycle-mover` changes an active user's groups, pushes each changed
  group, and checks the groups that the next ID token or userinfo response,
  and the next SAML assertion, actually carried.
- `lifecycle-leaver` deactivates the user, ends their IdP sessions, records
  each back-channel logout token and the app's answer, revokes their tokens,
  and pushes `active=false` through SCIM.
- `lifecycle-saml-logout` offers `Send LogoutRequest` for each ended SAML
  session and settles the step when the SP's `LogoutResponse` arrives.
- `lifecycle-skips` marks steps for unused or unfinished protocols as skipped
  with the reason, and keeps running independent steps after a failure.
- `lifecycle-api` runs the same scenarios through the local API and reports a
  SAML logout step as `needs_browser` with a `browser_url`.

## How to get to it (user POV)

- Choose `Lifecycle` in the active-environment sidebar. The `Run a scenario`
  section has forms named `Joiner`, `Mover`, and `Leaver`.
- Each run appears below as a card headed `Joiner: …`, `Mover: …`, or
  `Leaver: …`, with a checklist table.
- Through the API, `POST /environments/{id}/lifecycle/joiner`, `/mover`, and
  `/leaver`, then `GET /environments/{id}/lifecycle/{run_id}`.

## Driving it with Browser

Preconditions:

- Local stubs: a SAML SP on `127.0.0.1:19013` whose `/acs` records the posted
  `SAMLResponse` and whose `/slo` verifies scimtest's `LogoutRequest` and
  answers with a `LogoutResponse` through the same binding; a SCIM target on
  `127.0.0.1:19014` that stores resources in memory; and a back-channel
  logout receiver on `127.0.0.1:19015` that records each `logout_token` and
  answers `200`. Check Redirect signatures with `cryptography` and POST XML
  signatures with `signxml`, run through `uv run --no-project --with signxml
  --with cryptography --with lxml`.
- An environment named Greendale with slug `greendale`, created through the
  API with OIDC client `greendale-portal`, redirect URI
  `http://127.0.0.1:19013/callback`, back-channel logout URI
  `http://127.0.0.1:19015/backchannel-logout` with session required, SAML
  entity ID `urn:greendale:sp`, ACS `http://127.0.0.1:19013/acs`, Single
  Logout URL `http://127.0.0.1:19013/slo`, `include_groups_claim: true`, and
  SCIM at `http://127.0.0.1:19014` with any bearer token.
- The Greendale sample is loaded and synced, so `POST /sync/start` reports
  `users 10 created` and `groups 3 created`.

- **Joiner.** Open `Lifecycle`. In the `Joiner` form, fill `Given name` with
  `Ian`, `Family name` with `Duncan`, `Email` with
  `ian.duncan@greendale.edu`, check `Faculty`, and choose `Run joiner`. The
  page jumps to `Joiner: Ian Duncan`. After it refreshes, every step is `OK`:
  the provision step lists `GET /Users?…filter=externalId…` and `POST /Users`
  with `201 Created`, and the group step lists `PUT /Groups/…`. The SCIM stub
  recorded the `POST /Users` with `userName` `ian.duncan@greendale.edu`.
- **Mover.** In the `Mover` form, pick Annie Edison, check `Faculty` under
  `Add to groups` and `Study Group` under `Remove from groups`, and choose
  `Run mover`. Both group pushes reach `OK`, and the two `Next …` steps show
  `Waiting` with the expected groups. Sign Annie in through `POST
  /oidc/authorize` with scope `openid email groups`, redeem the code, and
  call `POST /saml/sign-in`. The steps then read `The ID token carried the new
  groups: Faculty` and `The SAML assertion carried the new groups: Faculty`.
- **Mover error.** Choose `Run mover` with no group checked. An alert reads
  `choose at least one group to add or remove`.
- **Leaver.** Sign Troy Barnes in through the API over OIDC and SAML. In the
  `Leaver` form, pick Troy Barnes and choose `Run leaver`. The checklist shows
  `Deactivate Troy Barnes` and `End Troy Barnes's IdP sessions` as `OK`, the
  back-channel step with `Logout token` to the receiver and `HTTP 200 OK`,
  `Revoked 1 tokens`, and `PUT /Users/…` with `200 OK`. The receiver got a
  token whose `sid` matches the OIDC session, the SCIM stub recorded
  `active: false`, and userinfo with Troy's old access token answers `401`.
- **SAML logout.** The SAML step reads `Needs browser`. Pick `HTTP-POST` in
  its `Binding for SAML Single Logout for session …` selector and choose `Send
  LogoutRequest`. The browser passes through the stub and lands on `Signed
  out`, which reads `The service provider answered Success.` Reopen
  `Lifecycle`: the step is `OK` with `The SP's LogoutResponse: the SP answered
  Success`, and the run is `OK`. Repeat with a fresh leaver and the default
  `HTTP-Redirect` binding.
- **API.** `POST /lifecycle/leaver` for a signed-in user returns `202`. Its
  SAML step has status `needs_browser` and a `browser_url` that opens this
  run's card in the Lifecycle tab.

## Gotchas

- The page refreshes itself only while a SCIM push or logout token is in
  flight. A step that waits for a sign-in or a browser does not refresh it.
- A mover's checks settle on the next ID token, userinfo response, or SAML
  assertion issued to that user, even one the app did not request with the
  `groups` scope. Without that scope, the OIDC check fails with `carried no
  groups`.
- API sign-ins carry no browser cookie, so each one starts its own IdP
  session. A leaver then ends one OIDC session and one SAML session.
- Runs live in memory. Relaunching the run clears them, and the binary embeds
  the templates and CSS, so relaunch after changing either.
