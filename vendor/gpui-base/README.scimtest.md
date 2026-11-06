This vendored gpui-base 0.9.0 includes local focus, input and text-selection
changes described in docs/rust-parity.md.

Rich-text readers expose rendered text through a read-only text-area role so
VoiceOver can interact with the text. Native selection ranges share the rich
text's highlighting and Copy state, reveal offscreen text, and reject requests
from old document revisions. Text runs include current glyph geometry in
physical pixels, including after a display-scale change.

Four reader regressions cover Unicode, long runs, stale requests, Copy, reflow,
offscreen reveal and scaling. Native macOS verification covers About and long
release notes, including VoiceOver reading and keyboard Done. Native AT-SPI
reader selection and reader link activation remain open.

Editable input snapshots also publish physical glyph bounds and character
metrics, using the current window scale. They supply a full parent value for
multiline fields, including empty text. The existing password/value-exposure
guard still excludes private text, including after mask reveal. A regression
checks text and geometry across scale changes from 1 to 2 and back. Native macOS
checks cover Unicode selection bounds, horizontal and vertical scrolling,
multiline persistence, password privacy and VoiceOver word/line reading.
