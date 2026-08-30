# Load the Greendale sample

The Greendale sample gives the active environment ten named users and three
overlapping groups, including one inactive user.

## Sub-features

- `sample-empty-entry` loads the sample from an empty Users table.
- `sample-tools-entry` exposes the same action in Bulk tools.
- `sample-users` shows the ten user records and inactive state.
- `sample-groups` shows the three group records.
- `sample-repeat` adds nothing when loaded twice.

## How to get to it (user POV)

- Open an empty `Users` page and choose `Load Greendale sample` in the table.
- Choose `Bulk tools` in the active-environment sidebar, then choose `Load
  Greendale sample` in that dialog.

## Driving it with Browser

Preconditions:

- Greendale Portal exists and is the active environment.
- Its Users and Groups counts are 0.

- **Check the empty entry.** Choose the sidebar link `Users 0`. The table row
  says `No users yet` and has button `Load Greendale sample`. Capture this
  before-action state.
- **Load from Users.** Choose `Load Greendale sample` and expect navigation.
  The status reads `loaded the Greendale sample: 10 users and 3 groups`. The
  sidebar links become `Users 10` and `Groups 3`.
- **Confirm users.** The Users table contains row text for `Troy Barnes`,
  username `tbarnes`, and `troy.barnes@greendale.edu`. It also contains `Señor
  Chang`, username `schang`, and an `inactive` button. Capture the table after
  loading.
- **Confirm groups.** Choose `Groups 3`. The group table contains `Study Group`,
  `Faculty`, and `Air Conditioning Repair Annex`. Capture it as a second view
  of the stored sample.
- **Check Bulk tools entry.** Choose `Bulk tools`. Dialog `Bulk tools` has
  heading `Greendale sample`, text `10 named users (one inactive) and 3
  overlapping groups`, and button `Load Greendale sample`.
- **Load again.** Choose that button and expect navigation. Status reads `the
  Greendale sample is already loaded`, while the counts stay at 10 and 3.
- **Prove both submit paths when required.** Use a second fresh run to submit
  through Bulk tools before the empty-table button. The two entry pages share a
  server action, but each visible entry point needs its own proof.

## Gotchas

- The sample requires an active environment.
- Señor Chang is inactive on purpose and does not appear in the list-mode OIDC
  chooser.
- The empty-table button disappears after the first load. Use a new run to
  prove it again.
- Repeat loading is a successful no-op. Do not expect a second set of rows.
