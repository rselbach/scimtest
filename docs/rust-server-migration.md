# Rust tunnel server migration rehearsal

The Rust server uses the Go server's JSON state and command-line options. The
deployment recipe still builds Go. This guide describes the Rust candidate and
its rehearsal; it does not switch the deployed service.

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
The static-server CI job is configured to run hosted acceptance, actual
Go-client interoperability and executable migration tests for this target.
It then rebuilds the standalone release executable, checks its ELF architecture
and absence of dynamic-library dependencies, and runs migration and restart
tests against that exact artifact. Its hash must remain unchanged throughout
those tests. The separate build matters because Cargo unifies additional
dependency features while building tests.

Local static AMD64 checks use a native ARM64 compiler and QEMU user emulation.
The full hosted/client suites and the exact standalone artifact rehearsals
pass in that setup. Native AMD64 CI is configured but has not run for this
change.

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

The automated rehearsal runs the actual Go and Rust executables on one
disposable listener. A current Rust desktop runtime and the actual Go legacy
client remain running through Go → Rust → Go rollback → Rust. It checks stable
public names, OIDC discovery/JWKS/authorization/token/userinfo, SAML metadata,
signing-key publication, dashboard sessions, revocation deny records, name
release, and profile changes written in both directions. It also checks a failed
candidate preflight while Go remains running and pending enrollment expiry
across the transition.

The existing Go service can send a forwarded request before its registration
confirmation. The Rust client holds up to 32 such requests within one
message-sized aggregate until registration succeeds. Exceeding either limit
fails the connection without forwarding. In-flight forwarding retains its
separate 32-request limit. The WebSocket frame and message limits both allow
the protocol's 32 MiB body plus Base64 and header overhead.

```sh
GOFLAGS=-mod=readonly cargo test --locked -p scimtest-server --test migration
```

Shared hosted acceptance runs identical dashboard, enrollment and replacement
workflows against the full Go and Rust HTTP servers. The router comparison also
checks methods, errors, malformed forms and response privacy headers.

```sh
GOFLAGS=-mod=readonly cargo test --locked -p scimtest-server --lib shared_
```

For the browser pass, install Playwright CLI and run:

```sh
python3 crates/scimtest-server/tests/browser/verify.py
```

This starts isolated Go and Rust fixtures and a headless browser. Authorization,
token and user endpoints use a local test provider. The same browser workflow
checks sign-in and cookies, profile edits and confirmations, enrollment,
responsive authorization pages, live tunnel refresh, replacement, revocation,
restoration, name release and logout. The runner prints its artifact directory
under `build/rust-hosted-browser`, closes its browser sessions and removes the
disposable server state. Its ignored Rust fixture is not part of the ordinary
test count.

Current evidence and unfinished release checks are recorded in
[the parity checklist](rust-parity.md).
