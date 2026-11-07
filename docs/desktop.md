# Desktop app

The desktop app uses [Rune](https://github.com/anomalyco/rune) and its rune-kit
components, and runs the Rust identity engine in the same process.
The local JSON API, OIDC/SAML endpoints, directory and SCIM client share its
saved state. The window renders without a WebView.

## Run from source

Use stable Rust. macOS builds require an Apple silicon Mac, macOS 26 and Xcode.
Linux builds require the XKB, Wayland and Vulkan development libraries:

```sh
./packaging/rust/install-linux-deps.sh
```

Start the desktop or the headless API:

```sh
cargo run --locked -p scimtest-desktop
cargo run --locked -p scimtest-core --bin scimtest -- --no-open
```

Source builds work locally without GitHub enrollment. Their default state is
separate from the installed application's state. Use `--state-file` to select
a specific database. See [the preview guide](rust-preview.md) for the state
paths, API authentication and supported workflows.

## Check the UI headlessly

With `SCIMTEST_PREVIEW_STATE` set, the desktop opens that database without
starting the server and accepts Rune's headless flags. An empty database gets
the Greendale sample directory. Render a page, dump its element and
accessibility tree, or drive it with a script:

```sh
SCIMTEST_PREVIEW_STATE=/tmp/greendale.db cargo run -p scimtest-desktop -- \
  --snap users.png --theme dark
SCIMTEST_PREVIEW_STATE=/tmp/greendale.db cargo run -p scimtest-desktop -- \
  --snap editor.png --scene user-editor --tree editor.json
```

The scenes are listed in `SCENES` in `crates/scimtest-desktop/src/workspace.rs`.
Rune's README describes `--script` and the other flags.

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
architecture (`amd64` or `arm64`). Packages declare the window-system and Vulkan runtime dependencies.

The release workflow builds Rust, signs and notarizes the macOS app and DMG,
and checks installed Linux packages under Xvfb. Version-tag pushes publish the
archives, signed update feed, legacy appcast and Homebrew cask. The updater
retains its pinned signing key, Developer ID and notarization requirements.
Further accessibility work is tracked in [the future backlog](rust-accessibility.md).
