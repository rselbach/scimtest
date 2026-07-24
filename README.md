# scimtest

`scimtest` is a local web-only auth testing service. It combines:

- a SCIM sync control surface for local users and groups
- an OIDC authorization-code test IDP
- a SAML HTTP-POST test IDP

The repository also contains `scimtest-server`, the companion public tunnel
server used by `scimtest` release builds.

Users and groups form one shared directory stored in SQLite. Every environment
uses that directory for OIDC claims, SAML attributes, and optional SCIM
provisioning. Each environment has independent SCIM credentials, remote IDs,
sync state, operation history, and errors.
Existing environment-based databases are flattened automatically; their apps and
directory entries are preserved, and environment SCIM settings move onto apps.

## Run

```sh
go run ./cmd/scimtest
```

The admin server opens in your browser at `http://127.0.0.1:8080` by default. If
that port is occupied, it tries successively higher ports. Use `--port` (or the
`PORT` environment variable) to require a specific port from 1 through 65535
(startup fails if that port cannot be bound):

```sh
go run ./cmd/scimtest --port 8090
```

Use `--no-open` to start the server without opening the admin UI in a browser.

Only one process runs for each state file. Launching `scimtest` again opens the
existing admin UI and exits; use a different `SCIMTEST_STATE_FILE` for an
independent instance.

State is stored at the OS user config path under `scimtest/state.db`. Set `SCIMTEST_STATE_FILE` to use an isolated SQLite state file.

Use `--debug` to log redacted OIDC and SAML interactions. Use
`--debug-secrets` only when raw credentials, tokens, and assertions are required;
its output is sensitive.

## Config

The global settings modal configures the IDP base URL published in OIDC/SAML
metadata. Release builds automatically establish an application-authenticated
tunnel through `https://scimtest.rselbach.com`; no user token or tunnel name is
required. A random tunnel path is assigned and reused for the local installation
when available.

The environment selector in the top bar sets the context for the whole admin UI.
Sync, import, reset, remote IDs, status, traces, and errors always refer to that
environment. Environments without Sync enabled still use the shared directory
for OIDC and SAML. Editing a shared user or group marks it dirty in every
SCIM-enabled environment.

Starting a sync opens a live details view with one row per SCIM operation. The
view can be closed without stopping the sync and reopened from the inline
progress bar. Raw requests and responses remain available in the sync trace.

Leave IDP base URL empty when clients can reach the current request host. Set it when clients need a public tunnel or another externally reachable URL.

The built-in tunnel exposes only the OIDC and SAML endpoints. The admin UI and
its SCIM credentials remain available only on the loopback listener.

Release builds require the `SCIMTEST_APPLICATION_PROFILE_ID` GitHub Actions
variable and `SCIMTEST_APPLICATION_PRIVATE_SEED_BASE64` secret. The latter is
the standard base64 encoding of the raw 32-byte Ed25519 seed. Local source
builds omit the tunnel when no application identity is injected; tests generate
their own keys and do not read local key files.

The server application profile for release builds must allow these routes:

```text
GET /oidc/{slug}/.well-known/openid-configuration
GET /oidc/{slug}/jwks
GET,POST /oidc/{slug}/authorize
POST /oidc/{slug}/token
GET,POST /oidc/{slug}/userinfo
GET /saml/{slug}/metadata
GET,POST /saml/{slug}/sso
```

Convert an unencrypted OpenSSH Ed25519 private key to the required secret value
from the repository root:

```sh
just application-seed /path/to/id_ed25519
```

Tunnel startup diagnostics are written to the application log. They include
the server URL, profile and instance IDs, WebSocket handshake status,
registration stage, and retry delay. Private keys and seeds are never logged.
`automatic tunnel disabled: build has no embedded application identity` means
the binary was built without the release identity linker values.

## IDP Endpoints

Each environment can expose OIDC, SAML, or both:

- OIDC discovery: `/oidc/{slug}/.well-known/openid-configuration`
- OIDC authorize: `/oidc/{slug}/authorize`
- OIDC token: `/oidc/{slug}/token`
- OIDC userinfo: `/oidc/{slug}/userinfo`
- OIDC JWKS: `/oidc/{slug}/jwks`
- SAML metadata: `/saml/{slug}/metadata`
- SAML SSO: `/saml/{slug}/sso`

The OIDC flow signs RS256 ID tokens. SAML responses include a signed assertion. Signing material is generated on first run and stored in the SQLite state database.

## Tunnel Server

`scimtest-server` exposes selected routes from local applications through
public HTTP tunnels:

- a GitHub-authenticated management dashboard restricted to an authorized
  administrator
- no user API tokens
- no user-selected tunnel names
- no standalone generic tunnel client
- Ed25519-authenticated application instances with random, reusable names

Each application profile defines an OpenSSH Ed25519 public key, the HTTP
method/path combinations it may expose, and its request limits. A connecting
application proves possession of the matching private key. Its stable instance
ID lets the server reuse the same random public name after reconnecting.

### Run Locally

```sh
SCIMTEST_GITHUB_CLIENT_ID=... \
SCIMTEST_GITHUB_CLIENT_SECRET=... \
go run ./cmd/scimtest-server \
  --addr :7000 \
  --domain localhost:7000 \
  --dashboard-domain admin.localhost:7000 \
  --logs
```

Configure the GitHub OAuth app callback URL as
`http://admin.localhost:7000/auth/github/callback`. Open
`http://admin.localhost:7000/dashboard`, sign in with the authorized GitHub
account, and create an application profile. The dashboard must use a different
origin from public tunnels so tunnel applications cannot access its session
cookie.

Generate a key pair for an application if it does not already have one:

```sh
ssh-keygen -t ed25519 -f scimtest_application -N ''
```

Paste the contents of `scimtest_application.pub` into the profile. Routes use
one `METHOD[,METHOD] PATH` entry per line. Full path segments can be parameters:

```text
GET /scim/v2/ServiceProviderConfig
GET,POST /scim/v2/Users
GET,PUT,PATCH,DELETE /scim/v2/Users/{id}
```

### Embed the Tunnel Client

Applications use the public client package to connect. Loading an encrypted or
unencrypted OpenSSH private-key file as an `ed25519.PrivateKey` is the embedding
application's responsibility.

```go
import scimtestclient "github.com/rselbach/scimtest/client"

tunnel, err := scimtestclient.Start(ctx, scimtestclient.Config{
	ServerBaseURL:         "https://tunnels.example.com",
	ApplicationProfileID: "0123456789abcdef0123456789abcdef",
	InstanceID:            installationID,
	ApplicationPrivateKey: privateKey,
	LocalPort:             3000,
})
if err != nil {
	return err
}
defer tunnel.Close()

publicBaseURL := tunnel.PublicURL
```

Each tunnel uses its stable ID as a root path. For example, a tunnel with the
public URL `https://tunnels.example.com/human-timeline-club` exposes the
allowed route `/scim/v2/Users` at
`/human-timeline-club/scim/v2/Users`. The full public path, including the
tunnel root, is forwarded to the client application unchanged.

The client reconnects transient failures automatically. Invalid profile IDs,
instance IDs, or signatures are terminal errors.

### Production

Configure a reverse proxy to forward both the public tunnel host and the
separate dashboard host to the server:

```caddyfile
tunnels.example.com, admin.example.com {
	reverse_proxy 127.0.0.1:8000
}
```

```sh
scimtest-server \
  --addr 127.0.0.1:8000 \
  --domain tunnels.example.com \
  --dashboard-domain admin.example.com \
  --scheme https \
  --behind-proxy \
  --data /var/lib/scimtest-server/scimtest-server.json \
  --logs
```

Set `SCIMTEST_GITHUB_CLIENT_ID` and `SCIMTEST_GITHUB_CLIENT_SECRET` in the
service environment. The production OAuth callback URL is
`https://admin.example.com/auth/github/callback`.

`--behind-proxy` trusts `X-Forwarded-*` only from configured proxy networks.
The default trusted networks are loopback; use `--trusted-proxy-cidrs` when the
proxy runs elsewhere.

The JSON data file contains the dashboard whitelist and sessions, application
profiles, and remembered instance names. GitHub access tokens are not stored.

#### Deploy to exe.dev

The production server runs on the `scimtest` exe.dev VM. exe.dev terminates TLS
for `scimtest.rselbach.com` and `admin.scimtest.rselbach.com`, then forwards
both hosts to `127.0.0.1:8000`; the VM does not need Caddy.

The one-time VM setup requires the root-owned environment file at
`/etc/scimtest-server/scimtest-server.env`. Start from
`deploy/scimtest-server.env.example`, add the GitHub OAuth credentials, and
keep the file mode at `0600`. The OAuth application callback URL is
`https://admin.scimtest.rselbach.com/auth/github/callback`.

Deploy from a local checkout with:

```sh
just deploy-server
```

The recipe runs the tests, builds a static Linux/amd64 server, copies it and
the systemd unit over SSH, restarts the service, and checks the local port on
the VM. A failed restart or health check restores the previous binary and
unit. exe.dev must remain configured with a public proxy on port 8000 and both
custom domains registered.

The systemd unit, environment example, and deployment script live in
`deploy/`. Persistent application data remains in `/var/lib/scimtest-server`.

### Current Limits

One complete HTTP request and response is carried in each tunnel message.
Streaming and raw TCP forwarding are not supported, and request or response
bodies are capped by `--max-body` (32 MiB by default).
