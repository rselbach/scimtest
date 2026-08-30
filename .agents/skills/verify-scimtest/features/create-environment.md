# Create an environment

Environment setup names the app under test, enables its protocols, and publishes
the connection values that the user copies into that app.

## Sub-features

- `env-first-run` opens the setup wizard on an empty instance.
- `env-add-entry` opens the wizard from the getting-started guide and the
  Environments page.
- `env-save-oidc` saves Greendale Portal with OIDC enabled.
- `env-persist` shows the saved environment after reload.
- `env-discovery` serves discovery from the action card.

## How to get to it (user POV)

- Open a fresh scimtest instance. The `Add environment` dialog opens.
- Choose `Create a test environment` in the getting-started guide.
- Choose `Environments` in the Global sidebar, then `Add environment`.
- After saving, expand `Show options for Greendale Portal` and choose
  `Discovery JSON`.

## Driving it with Browser

Preconditions:

- A fresh run has passed doctor.
- The Environments count is 0.

- **Open the wizard.** Navigate to the run URL. The DOM has a dialog named
  `Add environment`, a textbox labeled `Environment name`, and a `Next` button.
  Capture this state as `create-environment/empty.aria.txt`.
- **Name the environment.** Fill `Environment name` with `Greendale Portal`.
  Choose `Next`. The selected tab is `2 OIDC Disabled`, and the page shows the
  `Enable OIDC` checkbox.
- **Configure OIDC.** Check `Enable OIDC`. Fill `Client ID` with
  `greendale-portal`. Check the `Unsafe redirect testing` group checkbox named
  `Allow arbitrary redirect URIs`. The OIDC tab changes from `Incomplete` to
  `Configured`. Capture the filled wizard before saving.
- **Save.** Choose `Save environment` inside the dialog and expect navigation.
  The result has status `environment added`, combobox `Active environment` with
  selected option `Greendale Portal`, link `Environments 1`, and text `OIDC ✓`.
- **Confirm persistence.** Reload. The same environment, count, and OIDC status
  remain. Capture `create-environment/after-reload.aria.txt` and a full-page
  screenshot.
- **Confirm discovery.** Choose `Show options for Greendale Portal` and observe
  link `Discovery JSON`. Read its `href`, then request that exact URL with curl.
  Capture the JSON body and headers. The issuer ends with
  `/oidc/greendale-portal`; `authorization_endpoint`, `token_endpoint`,
  `userinfo_endpoint`, and `jwks_uri` use the run origin.
- **Check other entry points.** Return to Environments and confirm `Add
  environment`. Follow it only far enough to observe a new `Add environment`
  dialog, then close it without saving. The getting-started entry is present
  only until its first step is complete, so verify it on a separate fresh run.

## Gotchas

- The accessible labels include their hint text. Use `exact: false` for
  `Environment name`, `Client ID`, and `Unsafe redirect testing`.
- Enabling OIDC without a client ID or redirect policy leaves the tab
  incomplete. The built-in playground needs the client ID.
- The generated endpoint name is `greendale-portal`. Do not derive another
  slug.
- The source runner accepts arbitrary redirect URIs only when that checkbox is
  checked. This setting is appropriate for the isolated loopback run.
- `localhost` is not interchangeable with the printed `127.0.0.1` origin. Use
  the exact launch URL.
- `Discovery JSON` has `target="_blank"`. Some browser clients block the raw
  JSON page. Prove the visible link in Browser, then use curl on its observed
  href.
