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

The **Desktop spike** workflow attaches unsigned Linux amd64 and Windows amd64
executables plus an ad-hoc-signed macOS arm64 app to each relevant pull request
run for 14 days. Extract the archive and run `scimtest-desktop`
(`scimtest-desktop.exe` on Windows), or open `scimtest.app` on macOS.

- Linux builds require GTK 3 and WebKitGTK 4.0 at runtime.
- macOS pull request apps use only an ad-hoc signature and are not notarized.
- Windows requires the Microsoft Edge WebView2 runtime included with current
  Windows releases.

The operating system may warn before launching an unsigned test build. Tagged
releases instead contain a signed and notarized universal macOS application.

## Build locally

Desktop builds use CGO and must be built on the target operating system. On
Debian or Ubuntu, install the native headers first:

```sh
sudo apt-get install build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.0-dev
```

Then inject the same public application profile ID used by release builds:

```sh
go build -tags desktop \
  -ldflags="-X=github.com/rselbach/scimtest/internal/web.tunnelApplicationProfileID=$SCIMTEST_APPLICATION_PROFILE_ID -X=github.com/rselbach/scimtest/internal/web.tunnelReleaseProfileRequired=true" \
  -o scimtest-desktop ./cmd/scimtest-desktop
```

On Windows, add `-H=windowsgui` to `-ldflags`. macOS needs Xcode Command Line
Tools; Windows needs a CGO-capable C++ toolchain. macOS release builds set
`MACOSX_DEPLOYMENT_TARGET=26.0`.

## macOS releases

Tagged releases build the desktop executable natively on Apple Silicon and
Intel macOS 26 runners. The release workflow combines both slices with `lipo`,
assembles `scimtest.app`, signs it with the hardened runtime and a secure
timestamp, and submits it to Apple's notary service. The accepted ticket is
stapled before the workflow creates the final ZIP and DMG. The DMG is separately
signed, notarized, and stapled.

The universal app supports macOS 26 and newer. Releases publish:

- `scimtest-desktop_<version>_universal.dmg`
- `scimtest-desktop_<version>_universal.zip`
- `scimtest-desktop_<version>_checksums.txt`

Homebrew installs the DMG through the separate `scimtest-desktop` cask. Tagged
releases no longer contain the browser-mode CLI; `cmd/scimtest` remains
available for source-based development. `scimtest-server` remains a separate
release artifact for tunnel operators. Publishing the first desktop release
also removes the legacy `scimtest` CLI cask from the tap; historical GitHub
release assets are not deleted.

The release environment requires these secrets:

- `MACOS_CERTIFICATE_P12_BASE64`: Developer ID Application certificate and
  private key exported as a base64-encoded PKCS #12 file
- `MACOS_CERTIFICATE_PASSWORD`: password protecting that file
- `APPLE_ID`: Apple Account email used for notarization
- `APPLE_APP_SPECIFIC_PASSWORD`: app-specific password for that Apple Account
- `APPLE_TEAM_ID`: Apple Developer team containing the Developer ID certificate
- `TAP_GITHUB_TOKEN`: write access to `rselbach/homebrew-tap`

The release job generates its temporary keychain password and discovers the
signing identity from the imported certificate. App Store Connect credentials
are not required; releases use Developer ID distribution outside the Mac App
Store.

The repository variable `SCIMTEST_APPLICATION_PROFILE_ID` remains required.
The release workflow loads signing credentials for `v*` tag pushes and the
explicit `spike/desktop-app` preview trigger. Pull request artifacts never
receive those secrets and remain unnotarized.

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
- Native menu commands beyond Quit, auto-update, and protocol/deep-link
  registration are not yet implemented.
- Linux artifacts dynamically depend on the distribution's WebKitGTK runtime.
