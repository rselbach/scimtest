This is AccessKit's macOS adapter, version 0.26.3.

The local patch raises live announcements after the other notifications in the
same tree update, preserving order within each group. This prevents a focus
notification from interrupting a result announcement when a form closes.
Native VoiceOver verification is recorded in docs/rust-parity.md.

The legacy `accessibilityIsAttributeSettable:` query also uses the existing
per-node permissions for value, focus, text-selection and selected-state
setters. Static status and error values therefore advertise as read-only;
editable fields retain value replacement and text selection.
