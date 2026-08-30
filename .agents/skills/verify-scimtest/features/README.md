# scimtest verification map

This directory is the maintained source for proving scimtest's user-facing
behavior. Read this index before driving the app, then follow the matching
feature file.

## Baseline preconditions

- Launch with `.agents/skills/verify-scimtest/scripts/control-scimtest launch`.
- Save the printed `RUN_ID` and `URL`, then require `doctor RUN_ID` to pass.
- Use the Browser skill against that exact URL. Never drive a user's default
  state file or an instance this run did not start.
- A fresh run has no environments. Opening `/` displays the `Add environment`
  dialog.
- Source builds keep OIDC and SAML on loopback because they have no public
  tunnel identity.

## Driving conventions

- Start each recipe from its stated preconditions.
- Use ARIA roles, accessible names, labels, and observed `data-*` attributes.
  Do not use coordinates or tab order.
- Take a fresh DOM snapshot after navigation and after any action that changes
  the page.
- Build a new run after source changes because the binary embeds templates and
  assets.
- Keep proof artifacts. Stop the run to discard its database and process.

## Proof and skip reporting

- Capture the actionable state before the click or submit and the resulting
  state afterward.
- Capture a screenshot when layout matters and an ARIA snapshot when labels or
  values matter.
- Confirm a mutation from a second user-facing view or after reload.
- Record the feature ID and entry point used with each artifact.
- Report an unreachable path with the attempted action and unmet precondition.
- Do not claim that one entry point proves another path listed in the map.

## Feature entry contract

Each feature file has an H1 title and one user-facing description, followed by
exactly four H2 sections in this order.

1. `Sub-features` names the behaviors.
2. `How to get to it (user POV)` lists every user entry point.
3. `Driving it with Browser` starts with `Preconditions:` and pairs exact
   actions with observable results.
4. `Gotchas` records traps that can invalidate a run.

## Features

- [Create an environment](./create-environment.md) covers the first-run wizard,
  OIDC setup, persistence, and discovery.
- [Load the Greendale sample](./greendale-sample.md) covers both sample entry
  points, directory rows, group rows, and repeat loading.
- [Run the OIDC playground](./oidc-playground.md) covers the built-in relying
  party, chooser, token exchange, claims, and inspector.
- [Export environment config](./config-export.md) covers the setup link and the
  machine-readable OIDC bundle.
