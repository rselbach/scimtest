# Run the OIDC playground

The OIDC playground is scimtest's built-in relying party. It runs a real
authorization-code flow, exchanges the code, and shows decoded claims and
userinfo.

## Sub-features

- `playground-card-entry` starts from the environment action card.
- `playground-inspector-entry` starts from OIDC Inspector.
- `playground-chooser` lists active users and signs in as Troy Barnes.
- `playground-sign-in-method` sends the chooser's sign-in method as `acr` and
  `amr`.
- `playground-session-reuse` offers the remembered sign-in on the next run and
  keeps its `auth_time`.
- `playground-result` shows the authorization and token results.
- `playground-jwt-access-token` decodes the access token when OIDC setup issues
  JWT access tokens.
- `playground-inspector` records the completed flow.

## How to get to it (user POV)

- On Environments, expand `Show options for Greendale Portal` and choose `Test
  with built-in RP`.
- For a public OIDC client, `Test sign-in` on the same card also opens the
  playground. Complete the chooser and confirm `Token response 200 OK` to
  verify that the PKCE verifier survives through code redemption.
- Open `OIDC Inspector` from the active-environment sidebar and use its
  playground action.
- Open `/inspect/oidc/greendale-portal/playground` on the run origin.

## Driving it with Browser

Preconditions:

- Greendale Portal has OIDC enabled with client ID `greendale-portal`.
- The Greendale sample is loaded.

- **Start from the card.** Choose `Environments 1`, expand `Show options for
  Greendale Portal`, and choose `Test with built-in RP`. Expect navigation.
- **Inspect the chooser.** The destination has heading `OIDC sign-in`, text
  `Greendale Portal`, searchbox `Search users`, radiogroup `Users`, and `9
  users`. It lists Troy Barnes and omits inactive Señor Chang. Capture
  `oidc-playground/chooser.aria.txt` and a screenshot.
- **Choose Troy.** Check the radio whose accessible name starts with `Troy
  Barnes`. The combobox `Sign-in method` shows `Password` selected. Select
  `Password + MFA`, then choose `Continue` and expect navigation.
- **Inspect the result.** The page heading is `OIDC playground`. It has headings
  `Authorization response`, `Token response 200 OK`, `Decoded ID token`, and
  `Userinfo`. Claims include name `Troy Barnes`, email
  `troy.barnes@greendale.edu`, username `tbarnes`, and groups `Study Group` and
  `Air Conditioning Repair Annex`. They also include `acr`
  `https://refeds.org/profile/mfa`, `amr` `pwd`, `otp`, and `mfa`, and an
  `auth_time`. Capture the result DOM and screenshot.
- **Refresh.** Choose `Refresh tokens`. The refreshed claims keep the same
  `auth_time` and `acr` with a later `iat`.
- **Reuse the session.** Start the playground again in the same tab. The
  chooser header shows `Signed in as Troy Barnes`, `Password + MFA`, the
  session age, and button `Reuse session`. Choose it. The new claims keep the
  first run's `auth_time`.
- **Check JWT access tokens.** In OIDC setup, check `Issue JWT access tokens
  (RFC 9068)`, set `Access token audience` to `https://api.greendale.edu`, and
  save. Reopen setup to confirm both values persisted. Run the playground
  again. The result adds heading `Decoded access token`, with header `typ`
  `at+jwt` and claims `aud` `https://api.greendale.edu`, `client_id`
  `greendale-portal`, `scope`, and `jti`. `Userinfo` still shows Troy.
- **Confirm the inspector.** Choose `Flow inspector`. The OIDC inspector shows
  the completed Troy flow and its successful hops. Capture it as the second
  view.
- **Check the inspector entry.** On a separate pass, open `OIDC Inspector`
  first and confirm its playground action reaches the same chooser. Do not run
  a second token exchange unless that path changed.

## Gotchas

- The chooser has nine users because inactive Señor Chang is excluded.
- The chooser radio accessible name includes Troy's email. Match the name with
  `/^Troy Barnes/`.
- The playground keeps state, nonce, and PKCE verifier in a browser cookie.
  Stay in the same tab through the chooser and callback.
- A discovery response or readiness check does not prove the playground. The
  proof requires chooser, code exchange, decoded token, and userinfo.
- After any sign-in, the chooser preselects that user and offers `Reuse
  session`. Use a fresh browser profile to see the first-run chooser.
- Adding `prompt=login` or a short `max_age` to an authorize URL replaces the
  `Reuse session` card with `requires a fresh sign-in (...)`.
- Token artifacts contain short-lived credentials. Keep them in the ignored
  artifact directory and do not paste the raw token into chat.
