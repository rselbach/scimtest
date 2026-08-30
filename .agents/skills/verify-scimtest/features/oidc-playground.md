# Run the OIDC playground

The OIDC playground is scimtest's built-in relying party. It runs a real
authorization-code flow, exchanges the code, and shows decoded claims and
userinfo.

## Sub-features

- `playground-card-entry` starts from the environment action card.
- `playground-inspector-entry` starts from OIDC Inspector.
- `playground-chooser` lists active users and signs in as Troy Barnes.
- `playground-result` shows the authorization and token results.
- `playground-inspector` records the completed flow.

## How to get to it (user POV)

- On Environments, expand `Show options for Greendale Portal` and choose `Test
  with built-in RP`.
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
  Barnes`, then choose `Continue` and expect navigation.
- **Inspect the result.** The page heading is `OIDC playground`. It has headings
  `Authorization response`, `Token response 200 OK`, `Decoded ID token`, and
  `Userinfo`. Claims include name `Troy Barnes`, email
  `troy.barnes@greendale.edu`, username `tbarnes`, and groups `Study Group` and
  `Air Conditioning Repair Annex`. Capture the result DOM and screenshot.
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
- Token artifacts contain short-lived credentials. Keep them in the ignored
  artifact directory and do not paste the raw token into chat.
