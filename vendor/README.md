Local dependency patches
========================

`gpui-base` is the published 0.9.0 crate from crates.io. Its original license
and source are retained. The local patch adds input text runs and selection
semantics for AccessKit so Linux assistive tools can read and navigate input
contents. Password values remain excluded from the accessibility tree.
Scrollable viewports also honor descendant autoscroll requests, revealing
focused inputs in long forms and propagating adjusted requests through nested
viewports. Inputs request this on focus and window viewport changes, so later
manual scrolling is preserved. Standalone regressions cover nested reveal and
manual scrolling with bouncing disabled, alongside the existing gesture tests.
Buttons and checkboxes emit the same reveal requests on focus and window resize.
Their retained state resets on blur, including while a control is unmounted,
so refocusing a remounted control reveals it again. This covers custom form
choices and inspector actions as well as text inputs.

Its local lockfile pins its standalone test dependencies. Run the input
regressions with `cargo test --manifest-path vendor/gpui-base/Cargo.toml --locked
--features test-support --lib input::`.

`accesskit` 0.24.1, `accesskit_atspi_common` 0.19.1, and `accesskit_unix` 0.22.1
are also vendored from crates.io with their original source and licenses. The
Unix adapter backports upstream EditableText support from AccessKit commit
`df0a19bab9125026ce2c2f6ac0f464909626563d`. It adds insertion, deletion, copy,
cut, and paste through the editor's existing validation, clipboard, and undo
paths. An additional `EditText` action carries the operation and its explicit
text range together so the editor can reject requests for stale text. Copying
a range preserves the current selection; disabled, read-only, and password
restrictions are checked again when the editor receives a request.
Cache additions and removals also keep their required structured D-Bus
arguments, so AT-SPI clients can consume those notifications.
Disabled controls omit the enabled and sensitive AT-SPI states; read-only
text remains available for reading and copying without exposing editing.

Each AccessKit crate has a standalone test lockfile. CI runs its unit tests as
well as the GPUI input tests and native package checks.

`gpui-pre-linux` 0.3.11 is the published crates.io snapshot of Zed commit
`f816e1f9263e3a8ef63c4baaa02e1441ce1c6038`, with its original source and license.
Its X11 adapter ignores temporary FocusIn/FocusOut events caused by keyboard
grabs. Orca uses these grabs for review commands; treating them as real focus
changes deactivates the window, resets input composition and interrupts screen
reader review. Normal focus changes, including changes while a grab is active,
still reach the window.

The adapter also supplies accessibility window bounds on initialization and
tree updates. X11 reports the existing scaled screen and content rectangles;
Wayland reports the scaled surface size at a zero origin because it does not
expose global positions. Without these bounds, Orca clips flat review to an
empty window and skips its contents.

Remove the patch when an upstream release supplies this behavior and passes the
native accessibility checks.
