# Desktop app

The desktop app uses GPUI and runs the Rust identity engine in the same process.
The local JSON API, OIDC/SAML endpoints, directory and SCIM client share its
saved state. The window renders without a WebView.

## Run from source

Use stable Rust. macOS builds require an Apple silicon Mac, macOS 26 and Xcode.
Linux builds require GPUI's font, window-system and Vulkan libraries:

```sh
./packaging/rust/install-linux-deps.sh
```

Start the desktop or the headless API:

```sh
cargo run --locked -p scimtest-desktop
cargo run --locked -p scimtest-core --bin scimtest-rust -- --no-open
```

Source builds work locally without GitHub enrollment. Their default state is
separate from the installed application's state. Use `--state-file` to select
a specific database. See [the preview guide](rust-preview.md) for the state
paths, API authentication and supported workflows.

## Beta downloads

Manually run **Release** on the rewrite branch with version `0.0.0`. Download
**scimtest-desktop-release** from the completed run for the signed, notarized
macOS ZIP and DMG. Linux artifacts contain Debian, Fedora and Arch packages.
Actions downloads remain available for seven days.

Manual runs do not publish a GitHub release, update feed, legacy Sparkle appcast
or Homebrew change. The beta's own updater is also disabled at version `0.0.0`.
Extract the beta into a separate folder and quit the installed app before
opening it. Full commands and checksum instructions are in
[the beta guide](rust-preview.md#verification).

## Build release packages

Release builds embed the public application profile ID and require GitHub
enrollment before the workspace and local test endpoints unlock:

```sh
SCIMTEST_APPLICATION_PROFILE_ID='<32-character-profile-id>' \
  ./packaging/rust/build-desktop.sh build/scimtest-desktop 0.0.0 macos
```

Use `deb`, `rpm` or `pkg.tar.zst` instead of `macos` for Linux. Each Linux
packaging script takes four arguments: binary, output package, version and
architecture (`amd64` or `arm64`). Packages include GPUI runtime dependencies.

The release workflow builds Rust, signs and notarizes the macOS app and DMG,
and checks installed Linux packages under Xvfb. Version-tag pushes publish the
archives, signed update feed, legacy appcast and Homebrew cask. The updater
retains its pinned signing key, Developer ID and notarization requirements.
Further accessibility work is tracked in [the future backlog](rust-accessibility.md).
