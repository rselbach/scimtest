# Tunnel server migration

The Rust server uses the Go server's JSON state and command-line options. The
deployment recipe builds Rust. This guide describes a manual cutover;
changing the branch does not switch the deployed service.

Build for the server's operating system and architecture:

```sh
cargo build --locked --release -p scimtest-server
```

The current hosted deployment target is Linux AMD64 and uses a static
executable. On an AMD64 Linux build host, install the musl compiler (for example,
`musl-tools` on Ubuntu), then build the Rust candidate with:

```sh
rustup target add x86_64-unknown-linux-musl
CC_x86_64_unknown_linux_musl=musl-gcc \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
  cargo build --locked --release --target x86_64-unknown-linux-musl \
  -p scimtest-server
```

The executable is `target/x86_64-unknown-linux-musl/release/scimtest-server`.
The static-server CI job checks the Rust service and tunnel client tests, then
verifies that the standalone server has no dynamic interpreter or shared-library
dependencies. The earlier Go comparison and migration rehearsal tests were
removed at the user's request. Keep the existing deployed executable for a
manual rollback; this branch does not retain its Go source.

Keep the public domain, dashboard domain, scheme, proxy trust, connect path,
limits, state path and GitHub OAuth environment unchanged during a cutover.
The OAuth callback remains on the dashboard domain. The desktop application
profile IDs, installation keys and reserved tunnel names remain valid.

Before switching an existing installation, preserve its Go executable, service
configuration and a private copy of its JSON state. Check the Rust candidate
against a separate state copy on a loopback listener. Confirm readiness, the
expected application profiles and the reserved names. An invalid state file
must fail startup without modifying that file or the running Go service.

Stop the Go service before starting Rust on its listener and state file. Only
one process may write a server state file. Take the final state snapshot after
Go has stopped, then start Rust with the existing options and environment.
Check `/ready`, the dashboard session, connected tunnel counts and a real
identity exchange through each required application. Existing clients reconnect
with their installation keys and reuse their public names. Requests in flight
can be interrupted by the socket restart.

Pending OAuth and enrollment requests live in memory and expire across server
restarts. Start those authorizations again after a cutover. Existing approved
installations, revocations and dashboard sessions live in the JSON file.

To roll back, stop Rust and restart the saved Go executable with the current
JSON state and the same configuration. This preserves profiles, enrollments,
revocations and name releases written after the upgrade. Keep the pre-upgrade
snapshot separately so it cannot silently replace newer changes.

Test the cutover with a disposable state copy before changing the live service.
Run the remaining Rust service checks with:

```sh
cargo test --locked -p scimtest-server -p scimtest-protocol
cargo test --locked -p scimtest-core --test tunnel --test connection
```

The Rust client buffers bounded early traffic until registration succeeds,
then preserves the public URL across reconnects. Recheck sign-in, enrollment,
revocation, reserved names and reconnects manually against the candidate build.

Current features and unfinished release checks are recorded in
[the parity checklist](rust-parity.md).
