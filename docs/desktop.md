# Desktop app

The desktop preview wraps scimtest's existing Go HTTP server and embedded,
server-rendered UI in the operating system's WebView. It does not introduce a
JavaScript application or duplicate the backend behind a desktop RPC layer.

```text
Native window (WKWebView / WebView2 / WebKitGTK)
                       │
                       ▼
             http://127.0.0.1:<port>
                       │
                       ▼
            existing internal/web server
```

`github.com/webview/webview_go` is deliberately used instead of Electron or a
larger application framework. scimtest already owns navigation, forms, assets,
and application behavior, so the desktop-specific code only needs to manage a
window and server lifecycle.

## Try a PR build

The **Desktop spike** workflow attaches four packages to each relevant pull
request run for 14 days:

- an ad-hoc-signed macOS arm64 ZIP
- an Ubuntu 24.04 amd64 `.deb` package
- a Fedora 44 x86_64 `.rpm` package
- an Arch Linux x86_64 `.pkg.tar.zst` package

Extract the ZIP and open `scimtest.app` on an Apple silicon Mac. Install the
Linux packages with `apt`, `dnf`, or `pacman -U`, respectively.

- macOS pull request apps use only an ad-hoc signature and are not notarized.

The operating system may warn before launching an ad-hoc-signed test build.
Tagged releases contain a signed and notarized macOS arm64 application.

## Build locally on macOS

Desktop builds use CGO and require an Apple silicon Mac with Xcode Command Line
Tools. Fetch the pinned Sparkle framework first:

```sh
just fetch-sparkle
```

Then inject the same public application profile ID used by release builds:

```sh
go build -tags desktop \
  -ldflags="-X=github.com/rselbach/scimtest/internal/web.tunnelApplicationProfileID=$SCIMTEST_APPLICATION_PROFILE_ID -X=github.com/rselbach/scimtest/internal/web.tunnelReleaseProfileRequired=true" \
  -o scimtest-desktop ./cmd/scimtest-desktop
```

Release builds set `MACOSX_DEPLOYMENT_TARGET=26.0`.

Run the macOS desktop tests with Sparkle on the dynamic library search path:

```sh
DYLD_FRAMEWORK_PATH="$PWD/build/sparkle" \
  go test -tags desktop ./cmd/scimtest-desktop
```

## Build locally on Linux

Linux desktop builds use GTK 3 and WebKitGTK 4.1. On Ubuntu 24.04, install the
compiler and development packages:

```sh
sudo apt install g++ libgtk-3-dev libwebkit2gtk-4.1-dev pkg-config
```

The pinned `webview_go` binding requests the old `webkit2gtk-4.0` pkg-config
name. The Linux build adapter changes that request to `webkit2gtk-4.1`; it does
not change compiler or linker flags from the installed package.

Run the Linux desktop tests:

```sh
just test-desktop-linux
```

Build with the release application profile:

```sh
just build-desktop-linux "$SCIMTEST_APPLICATION_PROFILE_ID"
```

The executable is written to `bin/scimtest-desktop`.

## macOS releases

Tagged releases build the arm64 desktop executable on an Apple silicon macOS 26
runner. The release workflow assembles `scimtest.app`, signs it with the
hardened runtime and a secure timestamp, and submits it to Apple's notary
service. The accepted ticket is stapled before the workflow creates the final
ZIP and DMG. The DMG is separately signed, notarized, and stapled.

The app supports Apple silicon Macs running macOS 26 and newer. Releases
publish:

- `scimtest-desktop_<version>_arm64.dmg`
- `scimtest-desktop_<version>_arm64.zip`
- `scimtest-desktop_<version>_checksums.txt`

Homebrew installs the DMG through the separate `scimtest-desktop` cask. Tagged
releases no longer contain the browser-mode CLI; `cmd/scimtest` remains
available for source-based development. `scimtest-server` remains a separate
release artifact for tunnel operators. Publishing the first desktop release
also removes the legacy `scimtest` CLI cask from the tap; historical GitHub
release assets are not deleted.

## Linux releases

Tagged releases publish native packages for Ubuntu 24.04, Fedora 44, and Arch
Linux on amd64/x86_64:

- `scimtest-desktop_<version>_linux_amd64.deb`
- `scimtest-desktop_<version>_linux_x86_64.rpm`
- `scimtest-desktop_<version>_linux_x86_64.pkg.tar.zst`

Each package installs the executable, desktop entry, icon, and license. It uses
the distribution's GTK and WebKitGTK libraries rather than bundling them.

The release workflow compiles each executable inside its target distribution,
installs the finished package, and runs it under Xvfb. It verifies that the
native window opens, loads the GitHub account gate from the local server, and
shuts down when the window closes.

Linux releases do not include an automatic updater. Install a newer `.deb`
package to update the app.

The release environment requires these secrets:

- `MACOS_CERTIFICATE_P12_BASE64`: Developer ID Application certificate and
  private key exported as a base64-encoded PKCS #12 file
- `MACOS_CERTIFICATE_PASSWORD`: password protecting that file
- `APPLE_ID`: Apple Account email used for notarization
- `APPLE_APP_SPECIFIC_PASSWORD`: app-specific password for that Apple Account
- `APPLE_TEAM_ID`: Apple Developer team containing the Developer ID certificate
- `SPARKLE_EDDSA_PRIVATE_KEY`: private key that signs Sparkle update archives
- `TAP_GITHUB_TOKEN`: write access to `rselbach/homebrew-tap`

The release job generates its temporary keychain password and discovers the
signing identity from the imported certificate. App Store Connect credentials
are not required; releases use Developer ID distribution outside the Mac App
Store.

The repository variable `SCIMTEST_APPLICATION_PROFILE_ID` remains required.
GitHub Pages must use GitHub Actions as its source so the release workflow can
publish `https://rselbach.github.io/scimtest/appcast.xml`.
The release workflow loads signing credentials for `v*` tag pushes and the
explicit `spike/desktop-app` preview trigger. Pull request artifacts never
receive those secrets and remain unnotarized.

The signed macOS app checks that appcast through Sparkle. Scheduled update
checks are enabled by default; installing an available update still requires
the user to approve it. Users can also choose **scimtest > Check for Updates…**.
The first release that contains Sparkle must
still be installed through Homebrew or a manual download. Later releases can
replace it in place.

## GitHub account gate

Desktop mode requires the release application profile and starts locked. On a
new installation it shows the sign-in action in the desktop window, opens the
GitHub OAuth flow in the default browser, and polls for approval. The server
issues a short-lived, single-use browser handoff URL so the app's action can
redirect directly to GitHub without showing a second confirmation page.
The local admin UI and local OIDC/SAML endpoints return `401` until the enrolled
installation key authenticates to the tunnel server.

The tunnel server performs the OAuth code exchange with PKCE. The desktop
binary never contains a GitHub OAuth client secret and never stores the GitHub
access token. It persists the existing per-installation Ed25519 key in the
scimtest state database; the server records which GitHub account enrolled that
key. The app bar shows **Signed in as @login** when a matching server reports
the login. Older deployed servers still prove enrollment but can only show the
explicit **Signed in with GitHub** fallback until upgraded.

**Log out** closes the current tunnel, atomically replaces the local
installation ID and private key, and returns the app to the account gate for a
fresh GitHub authorization. This forgets the account on this computer. The old
installation remains as an inactive record on the tunnel server until an
operator removes or revokes it.

Closing the native window cancels and gracefully shuts down both local HTTP
listeners and the tunnel. A browser-mode scimtest process must be stopped before
starting desktop mode so it cannot bypass the desktop account gate.

## Known spike limitations

- Account switching uses **Log out** followed by a new GitHub authorization.
- Each launch needs network access long enough to authenticate the installation
  tunnel. The app locks again if that tunnel disconnects.
- Linux auto-update and protocol/deep-link registration are not yet implemented.
- Linux releases currently support Ubuntu 24.04, Fedora 44, and Arch on
  amd64/x86_64.
