# Export environment config

Config export gives a user or CI job a machine-readable connection bundle for
one environment, including its OIDC client secret.

## Sub-features

- `config-setup-entry` exposes the download in OIDC setup.
- `config-json` returns the active environment's OIDC bundle.
- `config-missing` returns not found for an unknown environment ID.

## How to get to it (user POV)

- Choose `Set up this environment`, open the `OIDC Configured` tab, and choose
  `Download config JSON`.
- Fetch the documented admin route `/apps/{environment-id}/config.json` on the
  loopback run origin.

## Driving it with Browser

Preconditions:

- Greendale Portal exists with OIDC enabled.
- Doctor passes for the same run.

- **Open setup.** Choose `Set up this environment`. Dialog `Set up environment`
  opens. Choose the tab whose name matches `OIDC Configured`.
- **Find the download.** The OIDC panel shows issuer, discovery, authorize,
  token, and JWKS values, plus link `Download config JSON`. Read that link's
  `href`; it is `/apps/<environment-id>/config.json`.
- **Read the bundle.** Request the run origin plus that observed href with curl.
  Capture the response headers and body. Status is 200 and JSON has environment
  `Greendale Portal`, slug
  `greendale-portal`, and OIDC values for `issuer`, `discovery_url`,
  `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`,
  `client_id`, and `client_secret`.
- **Confirm the origin.** Every OIDC URL starts with the exact loopback run URL.
  The admin route is not a public tunnel path.
- **Check a missing ID.** Request `/apps/does-not-exist/config.json` with curl on
  the same origin. The response is 404.
- **Capture proof.** Save the JSON body and response headers under
  `config-export/`. Redact the client secret from any prose report.

## Gotchas

- The export contains a live client secret for this disposable state file.
  Keep the artifact ignored and local.
- Use the href observed in the setup dialog. Environment IDs change between
  runs.
- A real-looking ID from another run returns 404 because each run has an
  isolated database.
- Source builds have no public tunnel, but config export remains available on
  the local admin origin.
- The browser may block a raw JSON document, and the setup link uses download
  behavior. Prove the link in Browser and read its observed href with curl.
