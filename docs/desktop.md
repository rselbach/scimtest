# Desktop spike

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

The **Desktop spike** workflow attaches unsigned Linux amd64, macOS arm64, and
Windows amd64 archives to each relevant pull request run for 14 days. Extract
the archive and run `scimtest-desktop` (`scimtest-desktop.exe` on Windows).

- Linux builds require GTK 3 and WebKitGTK 4.0 at runtime.
- macOS builds are raw, unsigned executables rather than `.app` bundles.
- Windows requires the Microsoft Edge WebView2 runtime included with current
  Windows releases.

The operating system may warn before launching an unsigned test build.

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
Tools; Windows needs a CGO-capable C++ toolchain.

## GitHub account gate

Desktop mode requires the release application profile and starts locked. On a
new installation it shows the existing tunnel enrollment page in the desktop
window, continues through GitHub OAuth there, and polls for approval. The local
admin UI and local OIDC/SAML endpoints return `401` until the enrolled
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
- GitHub OAuth currently runs in the embedded system WebView as requested. A
  production pass should validate this user-agent choice against GitHub policy
  and compare it with an external browser plus a loopback return.
- Packaging, code signing, notarization, icons, native menus, auto-update, and
  protocol/deep-link registration are intentionally outside this spike.
- Linux artifacts dynamically depend on the distribution's WebKitGTK runtime.
