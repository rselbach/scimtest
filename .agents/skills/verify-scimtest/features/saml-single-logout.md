# Run SAML Single Logout

SAML Single Logout ends IdP sessions from either side. A service provider
sends a `LogoutRequest` to scimtest's Single Logout URL, or the tester sends
one to the SP from the SAML inspector. Each message is signed, and the SP's
answer comes back through the browser.

## Sub-features

- `slo-setting` stores the SP's Single Logout URL from SAML setup, and the
  setup panel shows scimtest's own Single Logout URL.
- `slo-metadata` advertises `SingleLogoutService` for HTTP-Redirect and
  HTTP-POST at `/saml/{slug}/slo`.
- `slo-session-index` puts the session's `SessionIndex` in the assertion and
  lists it, with the NameID, in the SAML inspector's `IdP sessions` table.
- `slo-idp-initiated` sends a signed `LogoutRequest` from the inspector over
  either binding, ends the session, and records the SP's `LogoutResponse`.
- `slo-sp-initiated` answers the SP's `LogoutRequest` with a signed
  `LogoutResponse` through the same binding and ends the session.
- `slo-errors` answers a wrong NameID with `Requester`/`UnknownPrincipal` and
  rejects another issuer with a plain 400.
- `slo-records` shows each message in Recent activity and decoded in Traffic.

## How to get to it (user POV)

- Open the environment's settings, choose the `SAML` step, and fill `Single
  Logout URL`. The `Copy these values into your app` panel lists scimtest's
  `Single Logout URL`.
- Open `SAML Inspector` from the active-environment sidebar. After a SAML
  sign-in, its `IdP sessions` table has a binding selector and a `Send
  LogoutRequest` button per session.
- An SP sends its `LogoutRequest` to `/saml/{slug}/slo`, by GET for
  HTTP-Redirect or by POST for HTTP-POST.
- Through the API, `POST /environments/{id}/saml/logout` and `GET
  /environments/{id}/saml/logouts`.

## Driving it with Browser

Preconditions:

- An environment named Greendale with slug `greendale`, SAML enabled, SP
  entity ID `urn:greendale:sp`, and ACS URL `http://127.0.0.1:18997/acs`.
- The Greendale sample is loaded.
- A stub SP listens on `127.0.0.1:18997`. It must record the `SAMLResponse`
  posted to `/acs`, and start an SP-initiated logout at
  `/start-logout?binding=redirect|post` with the stored NameID and
  SessionIndex. At `/slo` it must verify a `SAMLRequest`'s signature and
  answer with an unsigned `LogoutResponse`, and verify and record a
  `SAMLResponse`. Check signatures with a library other than scimtest's, for
  example `cryptography` for Redirect query signatures and `signxml` for POST
  XML signatures, run through `uv run --no-project --with signxml --with
  cryptography --with lxml`.

- **Set the SP's URL.** Open `Set up this environment`, choose tab `3 SAML`,
  fill `Single Logout URL` with `http://127.0.0.1:18997/slo`, and choose
  `Save environment`. The setup panel lists scimtest's `Single Logout URL` as
  `{URL}/saml/greendale/slo`. Reopen the dialog and confirm the value persisted.
- **Sign in.** Open `{URL}/saml/greendale/sso`, check the radio whose name
  starts with `Troy Barnes`, and choose `Continue`. The stub's ACS page shows
  the NameID and a `SessionIndex` such as `saml-session_…`.
- **Inspect the session.** Open `SAML Inspector`. The `IdP sessions` table
  lists Troy Barnes with the NameID, the same SessionIndex, and protocol
  `saml`. Capture it.
- **IdP-initiated over POST.** Select `HTTP-POST` in `Binding for Troy Barnes's
  LogoutRequest` and choose `Send LogoutRequest`. The browser passes through
  the stub and lands on scimtest's `Signed out` page, which reads `The service
  provider answered Success.` The stub records a verified signature, the
  NameID, the SessionIndex, Issuer `{URL}/saml/greendale/metadata`, and
  `Reason` `urn:oasis:names:tc:SAML:2.0:logout:admin`. Reopen the inspector:
  the `IdP sessions` table is gone, `Single Logout requests` shows the request
  with `the SP answered Success`, and Recent activity shows `saml logout` and
  `idp session` rows.
- **IdP-initiated over Redirect.** Sign in again. The chooser must not offer
  `Reuse session`. Send the LogoutRequest with the default `HTTP-Redirect`
  binding and expect the same `Signed out` page.
- **SP-initiated over Redirect and POST.** Sign in again, then open
  `http://127.0.0.1:18997/start-logout?binding=redirect`. The stub receives a
  `LogoutResponse` with a verified signature, status `Success`, its request ID
  in `InResponseTo`, and RelayState `sp-relay`. `GET /sessions` is empty.
  Repeat with `binding=post`.
- **Errors.** With a live session, send a Redirect `LogoutRequest` that keeps
  the session's SessionIndex but names `abed.nadir@greendale.edu`. The
  `LogoutResponse` carries `Requester` and `UnknownPrincipal`, and the session
  stays. A request whose Issuer is `urn:city-college:sp` gets a plain 400.
- **Traffic.** Open `Traffic`. Entries titled `SAML Single Logout` show each
  logout message decoded.

## Gotchas

- Single Logout needs the SP's `Single Logout URL`. Without it, the inspector
  disables `Send LogoutRequest` and SP-initiated requests get a 400.
- Sending a LogoutRequest from the inspector ends the session before the SP
  answers. Ending a session any other way, such as from OIDC Inspector or by
  deactivating the user, does not notify the SP.
- When the environment pins an SP request-signing certificate, the stub SP must
  sign its `LogoutRequest` and `LogoutResponse` messages, as it would sign
  AuthnRequests.
- The SP's `LogoutResponse` must name scimtest's request in `InResponseTo`.
  scimtest accepts one answer per request, so a replayed response gets a 400.
- Sessions live in memory. Restarting the run ends them, and a pending
  LogoutRequest can no longer be answered.
