This is gpui-pre-macos 0.3.11, pinned to the upstream GPUI snapshot at
Zed revision f816e1f9263e3a8ef63c4baaa02e1441ce1c6038.

The local patch installs AccessKit on GPUIView, which is the native keyboard
responder, instead of the surrounding window content view. This lets AppKit
resolve the focused accessibility element from the same view that receives
keyboard input. See docs/rust-parity.md for native verification coverage.
