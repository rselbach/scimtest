---
name: verify-scimtest
description: Drive scimtest's local web UI in a browser and prove environment setup, directory samples, OIDC playground flows, and config export. Use after changing user-facing behavior or when a real source-build check is needed.
---

# Verify scimtest

scimtest's primary user interface is the server-rendered admin UI. The source
runner also serves OIDC and SAML endpoints. The native desktop app wraps the
same UI but requires a GitHub-linked release profile, and `scimtest-server` is a
separate tunnel operator service. Use `./cmd/scimtest` for local verification.

Read `features/README.md`, then read the feature file that matches the change.
Drive every entry point listed there. A result from one convenient route does
not prove the other listed paths.

## Launch

From the repository root, run:

```sh
.agents/skills/verify-scimtest/scripts/control-scimtest launch
```

The helper prints a `RUN_ID`, `URL`, state file, log, artifact directory, and
tmux monitor command. Keep the run ID for every later helper call. It builds
`./cmd/scimtest`, chooses a free port from 18765 through 18865, starts with
`--no-open` in a private tmux session, and stores SQLite state under
`runs/<run-id>/`.

Launch is complete when the server log contains `scimtest is running` and the
helper's doctor check prints `doctor: ok`. Source builds report that the public
tunnel is unavailable. That is expected.

Each run has its own port, state file, and PID under
`/tmp/scimtest-verification/scimtest/runs/<run-id>/`. Parallel runs are safe when
they use different run IDs. Never drive the default state file or an instance
that this helper did not start.

Stop the instance with:

```sh
.agents/skills/verify-scimtest/scripts/control-scimtest stop RUN_ID
```

## Doctor

Run this before browser work whenever the instance looks wrong:

```sh
.agents/skills/verify-scimtest/scripts/control-scimtest doctor RUN_ID
```

Doctor checks that the recorded process is the run's built binary, that it owns
the recorded loopback port, and that its state file is inside the run directory.
It reads the instance token from `<state-file>.lock`, requires `GET /-/ready` to
return 204, follows `GET /` to a page containing `scimtest`, and rejects the
desktop-only GitHub account gate.

If doctor fails, inspect the `LOG_FILE` printed by `meta`, stop that run, and
launch a new one. Do not switch to an unverified port.

## Drive

Use the `browser:control-in-app-browser` skill. Select the exact `URL` printed by
launch, create a new tab, and inspect a DOM snapshot before acting. Use the
documented Browser Playwright interface, ARIA roles, accessible names, and
labels. Do not use screen coordinates.

Start a browser drive like this after replacing the URL with the launch value:

```js
const scimtestTab = await browser.tabs.new();
await scimtestTab.goto("http://127.0.0.1:PORT/");
nodeRepl.write(await scimtestTab.playwright.domSnapshot());
```

A fresh run opens the `Add environment` dialog. This is the observed OIDC setup
path:

```js
const environmentDialog = scimtestTab.playwright.getByRole("dialog", {
  name: "Add environment",
});
await environmentDialog.getByLabel("Environment name", {exact: false})
  .fill("Greendale Portal");
await environmentDialog.getByRole("button", {name: "Next", exact: true}).click();
await environmentDialog.getByLabel("Enable OIDC", {exact: true}).check();
await environmentDialog.getByLabel("Client ID", {exact: false})
  .fill("greendale-portal");
await environmentDialog.getByLabel("Unsafe redirect testing", {exact: false})
  .check();
await scimtestTab.playwright.expectNavigation(
  () => environmentDialog.getByRole("button", {
    name: "Save environment",
    exact: true,
  }).click(),
  {waitUntil: "domcontentloaded"},
);
```

The result must show status `environment added`, `Greendale Portal` in the
active-environment combobox, `Environments 1`, and `OIDC ✓`. Reload and check
those values again to prove persistence. Use the selected feature file for the
rest of the drive.

The binary embeds templates and assets. After any source change, stop the old
run and launch a new one. Reloading an old binary cannot show the change.

## Evidence

Store proof under `/tmp/scimtest-verification/scimtest/artifacts/<run-id>/`. Ask
the helper for an absolute destination before writing each file:

```sh
.agents/skills/verify-scimtest/scripts/control-scimtest artifact-path RUN_ID create-environment/before-save.aria.txt
.agents/skills/verify-scimtest/scripts/control-scimtest artifact-path RUN_ID create-environment/after-save.png
```

Write Browser output to those returned paths. For example:

```js
const fs = await import("node:fs/promises");
await fs.writeFile(beforePath, await scimtestTab.playwright.domSnapshot(), "utf8");
await fs.writeFile(afterImagePath, await scimtestTab.screenshot({fullPage: true}));
```

Proof must include the action state and the result, not only the final page.
Exercise the same form, link, chooser, or download that a user reaches. Do not
insert SQLite rows, call unexported Go helpers, or use test-only endpoints.
After a mutation, reload or use a second user-facing view to confirm the stored
value. For an OIDC flow, capture the chooser and the playground result or flow
inspector. For a JSON link or download, read its observed href with curl and
capture the response body and headers. Some browser clients block raw JSON
documents even when the app returns them correctly.

Mocks are acceptable only at an existing production boundary, such as a local
SCIM target used in place of a third-party service. Prove the local request and
the target's recorded side effect. `GET /-/ready` is a doctor check, not feature
evidence.

Config exports and backups contain secrets. Their artifact directories are
ignored by Git, but they still remain on disk. Do not paste their full contents
into chat or commit them.

## Cleanup

Close the Browser tab, then stop only the recorded run:

```sh
.agents/skills/verify-scimtest/scripts/control-scimtest stop RUN_ID
```

The helper verifies the PID still belongs to that run before sending a signal.
It never kills by process name. Stop removes `runs/<run-id>/`, including the
binary and SQLite state. It leaves `artifacts/<run-id>/` intact.

After cleanup, check both conditions:

```sh
test ! -e /tmp/scimtest-verification/scimtest/runs/RUN_ID
test -d /tmp/scimtest-verification/scimtest/artifacts/RUN_ID
```

Run cleanup after failed attempts too. If the helper refuses because the PID no
longer belongs to its binary, inspect the recorded metadata before removing any
scratch state.

## Helpers

`.agents/skills/verify-scimtest/scripts/control-scimtest` is executable and has
these commands:

- `launch [RUN_ID]` builds and starts an isolated source instance.
- `doctor RUN_ID` checks ownership, readiness, and the correct UI mode.
- `meta RUN_ID` prints the run's URL, PID, state, log, and artifact directory.
- `artifact-path RUN_ID RELPATH` creates the artifact parent and prints its
  absolute path.
- `stop RUN_ID` stops the owned process and removes only that run's scratch
  directory.

The helper requires Bash, Go, curl, lsof, ps, sed, and tmux.
