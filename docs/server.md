# scimtest-server

`scimtest-server` is the companion public tunnel server used by `scimtest`
release builds. This document covers operating it; regular scimtest users
never need it.

`scimtest-server` exposes selected routes from local applications through
public HTTP tunnels:

- a GitHub-authenticated management dashboard restricted to an authorized
  administrator
- no user API tokens
- no user-selected tunnel names
- no standalone generic tunnel client
- Ed25519-authenticated application instances with random, reusable names

Each application profile defines an OpenSSH Ed25519 public key, the HTTP
method/path combinations it may expose, and its request limits. That key only
authorizes enrolling new installations: each installation generates its own
Ed25519 key, and its first connection enrolls the public half under an
instance ID derived from the key's fingerprint. Later connections authenticate
with the installation key alone, so rotating the application key never breaks
enrolled installations. The stable instance ID lets the server reuse the same
random public name after reconnecting; new enrollments are rate limited per
client IP, and individual installations can be revoked from the dashboard.

Clients that predate installation keys authenticate every connection with the
application key and a client-chosen instance ID. The server still accepts this
legacy handshake, and an enrolling client that presents the legacy ID carries
its remembered public name over to the enrolled identity.

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
application's responsibility. `InstancePrivateKey` is the installation's own
generated key; persist it locally and reuse it so the installation keeps its
identity and public name.

```go
import scimtestclient "github.com/rselbach/scimtest/client"

tunnel, err := scimtestclient.Start(ctx, scimtestclient.Config{
	ServerBaseURL:         "https://tunnels.example.com",
	ApplicationProfileID: "0123456789abcdef0123456789abcdef",
	InstanceID:            installationID,
	ApplicationPrivateKey: privateKey,
	InstancePrivateKey:    installationKey,
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
