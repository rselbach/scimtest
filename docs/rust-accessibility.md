# Future native accessibility work

Further accessibility work is deferred at the user’s request. The existing
implementation and verification evidence below are retained for a future pass.

- [ ] Repeat the native checks on Rune. The desktop moved from GPUI to Rune,
  which builds its accessibility tree on upstream AccessKit 0.25. Everything
  recorded below was verified on the GPUI build with local GPUI and AccessKit
  patches that no longer exist; repeat the VoiceOver and Orca (X11 and Wayland)
  walkthroughs before relying on it. Upstream `accesskit_unix` 0.24 and later
  expose AT-SPI EditableText, which the old patches backported.

- [ ] Keyboard navigation and native accessibility for custom GPUI controls.
  Earlier native macOS checks covered named controls, tables, dialogs,
  inspector payloads, dropdown activation, password privacy, and Save/Find.
  Current GPUI tests cover modal focus, multiline saves, and dropdown keys.
  Local GPUI/AccessKit patches expose Linux AT-SPI Text and all six EditableText
  methods, including real clipboard copy/cut/paste, Unicode ranges, validation,
  undo, and rejection of stale or disallowed edits. Cache notifications retain
  their required structured arguments. Native checks cover saved
  environments, user/group creation, memberships, Save/Find shortcuts, Escape,
  30 Tab transitions inside a dialog, and all 27 text fields across the four
  settings panels. Both password fields remain private after entering a value
  and revealing the mask. Orca announces fields, values, selection changes,
  and the tested forms. The patches pass 420 input tests, twenty app tests,
  and separate schema/bridge tests. Current macOS checks repeat Unicode text
  replacement, selection, Undo, multiline persistence, password privacy, and
  Save/Find. Native walkthroughs cover OIDC/SAML payloads, token revocation,
  session termination, fault forms and injection results, SCIM progress/traces
  and import previews, and joiner/mover/leaver step results and messages.
  Release notes expose their body text; lifecycle forms name their user and
  group addition/removal controls, and custom faults name the SAML status.
  Linux Orca walkthroughs now cover protocol sign-in, refresh, token/session
  controls, readable JSON/XML, faults, SCIM reconciliation/trace/import, and
  joiner/mover/leaver forms and results. Mover claims are observed through both
  native sign-ins. Selected sections expose their pressed state, and success
  and error messages are announced. Identity and SCIM actions also announce
  repeated identical results.
  The leaver fixture verifies deactivation, session termination, revocation,
  and SCIM; logout delivery is skipped without configured logout endpoints.
  The Linux adapter preserves focus during Orca keyboard grabs, supplies window
  geometry for flat review, and reports disabled controls correctly. X11 move,
  resize, and real focus changes pass. Wayland checks under nested Weston
  cover native environment setup, Unicode clipboard/undo, OIDC/SAML inspectors,
  faults, SCIM, lifecycle runs, backup save/restore through the desktop portal,
  traffic, release notes, and the local account screen with Orca speech.
  Directory rows reveal keyboard focus without overriding manual scrolling;
  a regression test covers both behaviors. Traffic entries expose selection,
  and information windows provide their text as an accessible value. Inspectors
  use the displayed active account when the previous selection is deactivated.
  Scrollable forms honor input reveal requests, including nested viewports;
  all 27 settings fields pass Tab and Shift-Tab traversal at the minimum window
  size. Multiline checks require the caret to stay visible. Group member rows
  also reveal their focused checkboxes. Regressions preserve manual scrolling
  and verify keyboard activation and saved membership. Native macOS checks
  reproduce and verify both visibility fixes. The 30 scroll tests pass, including
  nested reveal with bouncing disabled.
  Shared buttons and checkboxes now request visibility on focus and window
  resize, reset their reveal state on blur, and preserve manual scrolling.
  The full 1,556-test GPUI base suite passes. Native macOS and Wayland checks
  cover long fault and lifecycle forms, reverse traversal, fault arming, and
  saved group choices. Those joiner checks verify directory changes; SCIM is
  skipped because it is disabled in these fixtures. Wayland also verifies
  tabbing through 16 inspector sessions and ending the focused last session.
  Long dropdowns constrain their height and scroll the selected entry into
  view. A regression covers first/last entries, reverse traversal, selection,
  and focus restoration. Native macOS checks use 39 active accounts and a
  41-option manager picker, then verify the chosen OIDC session and saved
  manager ID. Keyboard reopening and Escape inside the user editor pass.
  Editor dialogs hide the workspace from accessibility navigation and expose
  modal semantics. Native macOS checks cover user/group dialogs, restoration
  after save or Escape, and nested manager menus with saved selections.
  Account screens move focus out of the workspace and restore it on return;
  regressions cover search and keyboard reopening from the toolbar. Real tunnel
  policy-close and Retry tests exercise the production account watcher: locking
  closes the editor, recovery restores search, and recreated controls return
  focus to the workspace so keyboard navigation remains usable. The earlier
  snapshot-only interruption test did not exercise that watcher and has been
  replaced. Connection changes within an open Account screen also validate
  focus after rendering. Workspace and Account scopes expose named accessibility
  groups. Native macOS checks verify policy-close recovery, an interrupted
  editor returning to usable search, and switching from Troy to Abed with a
  rotated installation identity. These checks use a local peer; enrollment and
  signature verification remain covered separately by shared acceptance tests.
  Native macOS checks also verify the toolbar keyboard round trip and About
  dismissal through Done or
  Escape, followed by keyboard reopening from Help. Wayland checks repeat
  user-dialog isolation, discard confirmation, saved user recovery, checkbox
  and choice edits, backdrop clicks, the Account toolbar keyboard round trip,
  and About dismissal/reopening after parent-window activation settles.
  Escape and backdrop clicks ask before discarding an edited form. Text,
  multiline, checkbox, membership and dropdown edits keep that warning active,
  including after values are reverted. Canceling the warning restores the
  draft and focus; explicit Cancel and Close dismiss directly. Regressions
  cover nested confirmation focus, Save suppression, both ends of a backdrop
  gesture, and replacing lifecycle forms. All twenty app tests pass on macOS
  and Linux. Native macOS checks cover all editable form types, including
  invalid multiline and generator drafts, recovered saves and discarded data.
  Information windows use a bounded, selectable reader for long notes, with
  wheel, arrow, page and document navigation. Header and Done remain outside
  the scrolling text. Regressions deliver real test-platform resize events and
  assert the actual 400×280 viewport, last-block visibility, retained selection
  and keyboard Done. Native macOS and Wayland checks reach the final paragraph
  of 60-chapter notes, reverse direction and close with Done or Escape. macOS
  also checks a reduced window; Wayland checks returning to Help.
  Workspace and dropdown regressions now deliver resize events and assert the
  actual 960×640 viewport, or 1000×600 for directory rows, before checking
  geometry and keyboard behavior. All seven older resize sites are revalidated.
  The macOS AccessKit adapter attaches to GPUI's native keyboard responder.
  Native before/after checks align AXFocused with GPUI focus, and VoiceOver
  announces workspace/search focus, Account entry and return, user-form fields,
  and focus restored after canceling a discard confirmation. Status and error
  elements supply live text values; the macOS bridge raises announcements after
  other notifications from the same update. Native captions verify User saved
  after modal closure, repeated Refreshed results, and repeated immediate fault
  validation errors with an intervening focus announcement. Editor errors also
  expose live alerts, including the fault/lifecycle footer. Idle environment
  labels remain outside live announcements. The legacy macOS attribute query
  now follows each node's setter permissions: static status/error values reject
  replacement, while search and form fields remain editable and search text
  selection still works. Eleven macOS platform tests pass, and CI runs them.
  Information readers expose rendered text as read-only text areas with native
  selection ranges and glyph bounds in physical pixels. Native macOS checks
  highlight and copy About text, reveal a selected occurrence in chapter 60 of
  release notes, and verify UTF-16 selection metadata and Retina range bounds.
  VoiceOver reads the selected word and current line in both readers; keyboard
  Done closes them. Clipboard contents and VoiceOver state are restored.
  Four new regressions cover Unicode and long runs, stale requests, Copy,
  offscreen reveal, retained selection through reflow, and display scaling.
  All 1,560 GPUI base tests and twenty app tests pass on macOS; twenty app tests
  and the four reader regressions pass on Linux with matching source hashes.
  Editable inputs now publish glyph bounds and character metrics in physical
  pixels too. A regression checks actual viewport geometry and scale changes
  from 1 to 2 and back. Native Retina checks align selected text with its visible
  highlight after an emoji, vertical textarea scrolling, and horizontal input
  scrolling. Textareas also publish their full accessible value, including an
  explicit empty value; saved custom attributes retain all 25 entries. Both
  password fields remain private through native value, range, selection and
  child queries before and after revealing the mask. VoiceOver reads the
  selected environment-name word, the selected word on line 24 of the textarea,
  and that line's text. The textarea speech check explicitly raises the preview
  after the automation cursor overlay intercepted an initial attempt. VoiceOver
  is restored to off; these checks do not establish complete screen-reader
  traversal or real movement between displays. All 1,561 GPUI base tests and
  twenty app tests pass on macOS, along with Clippy and formatting. Linux passes
  twenty app tests and five input accessibility tests with matching source hashes.
  Native AT-SPI reader selection, reader link activation, complete VoiceOver
  protocol/provisioning/lifecycle workflows and other controls, plus remaining
  keyboard coverage, remain open.
