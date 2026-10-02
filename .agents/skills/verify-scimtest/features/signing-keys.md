# Rotate signing keys

Each environment signs ID tokens and SAML assertions with its own key ring.
Rotation switches signing to a new key and keeps the old key in the JWKS and
SAML metadata for a grace period.

## Sub-features

- `keys-inspector-card` lists published keys in both inspectors.
- `keys-rotate-ui` rotates from an inspector with a chosen grace period.
- `keys-rotate-api` rotates through `POST /signing-keys/rotate`.
- `keys-publish` lists the active and retired keys in the JWKS and SAML
  metadata, and new tokens carry the new `kid`.
- `keys-isolation` leaves other environments on their own keys.
- `keys-stale-jwks` serves a JWKS without the active key through the
  `Stale JWKS` scenario.

## How to get to it (user POV)

- Open `OIDC Inspector` or `SAML Inspector` from the active-environment
  sidebar. The `Signing keys` card is below the flow details.
- Open `Fault Injection` from the sidebar and arm `Stale JWKS`.
- Call `GET` and `POST /api/v1/environments/{id}/signing-keys/rotate` on the
  local API.

## Driving it with Browser

Preconditions:

- Greendale Portal has OIDC and SAML enabled with endpoint name
  `greendale-portal`.
- A second environment, such as City College, exists with OIDC enabled.

- **Read the card.** Open `SAML Inspector`. Region `Signing keys` has a table
  with one row: `scimtest-dev`, `Signing`, `Shared default key`. Combobox
  `Keep the old key published for` shows `24 hours`. Capture the region.
- **Rotate.** Select `1 hour` and choose `Rotate signing key`. The page returns
  to the same inspector. The first row now has a new key ID, `Signing`, and a
  creation time. The `scimtest-dev` row reads `Retired, published until`
  a time one hour later. Recent activity has a `keys rotate` entry.
- **Check the endpoints.** With curl, `/oidc/greendale-portal/jwks` lists the
  new `kid` first and `scimtest-dev` second. `/saml/greendale-portal/metadata`
  has two `X509Certificate` elements. A new ID token's header names the new
  `kid`.
- **Check isolation.** `/oidc/city-college/jwks` still lists only
  `scimtest-dev`.
- **Check the OIDC entry.** Open `OIDC Inspector`. It shows the same
  `Signing keys` region and `Rotate signing key` button.
- **Stale JWKS.** Open `Fault Injection`, set the count to 1 on `Stale JWKS`,
  and arm it. The next JWKS request omits the active key; the one after it is
  complete. The run shows `completed`, and Recent activity records
  `Injected JWKS without the current signing key`.

## Gotchas

- Key IDs are random. Read them from the card or `GET /signing-keys` in each
  run.
- `No grace period` removes only the key being retired. An older key keeps its
  own published-until time.
- Times in the card are UTC; Recent activity uses local time.
- A backup carries the key ring. Restoring a backup puts its keys back,
  including the private keys, so keep backup artifacts private.
