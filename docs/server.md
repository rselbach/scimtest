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

Each application profile defines the HTTP method/path combinations it may
expose and its request limits. Each installation generates its own Ed25519 key.
On its first connection, the client proves possession of that key and opens a
dashboard-hosted page where the user authorizes the installation with GitHub.
The OAuth callback and token exchange happen on the server. The client receives
only a short-lived, single-use enrollment credential bound to its exact public
key; GitHub access tokens are never returned to it or stored.

Later connections authenticate with the installation key alone. Its stable
fingerprint-derived instance ID lets the server reuse the same random public
name after reconnecting. New enrollments are rate limited per client network
and GitHub account, and individual installations can be revoked from the
dashboard.

Clients that predate installation keys authenticate every connection with the
application key and a client-chosen instance ID. The server accepts this legacy
handshake only for instance IDs already present in its data file; possession of
the old shared key cannot create a new identity. A newly authorized installation
does not automatically claim a legacy public name: knowledge of a legacy ID is
not treated as sufficient proof of ownership. The legacy record and public name
remain until an administrator releases them from the dashboard; automatic
deletion would let anyone who learned its ID disable it. Rotating the profile's
legacy key separately disables authentication for every remaining legacy record.

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

The profile's OpenSSH Ed25519 public key is retained only for reconnecting
already-known legacy clients during migration. Generate one if needed:

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

Applications use the public client package to connect. `InstancePrivateKey` is
the installation's own generated key; persist it locally and reuse it so the
installation keeps its identity and public name. Generic clients should open
`URL` in the user's browser (or display it in a terminal) and show
`VerificationCode` independently for comparison with the page. A trusted local
UI may instead open `BrowserHandoffURL` to go directly to GitHub OAuth. That URL
is short-lived and single-use, so do not log or persist it.

```go
import (
	"log"

	scimtestclient "github.com/rselbach/scimtest/client"
)

tunnel, err := scimtestclient.Start(ctx, scimtestclient.Config{
	ServerBaseURL:         "https://tunnels.example.com",
	ApplicationProfileID: "0123456789abcdef0123456789abcdef",
	InstanceID:            installationID,
	InstancePrivateKey:    installationKey,
	LocalPort:             3000,
	OnEnrollmentRequired: func(enrollment scimtestclient.Enrollment) {
		log.Printf("Authorize this installation at %s and compare code %s", enrollment.URL, enrollment.VerificationCode)
	},
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

The client polls while the browser flow is pending, reconnects with the
single-use credential after approval, and then forgets it. It reconnects
transient failures automatically. Invalid profile IDs, instance IDs, or
signatures are terminal errors. `ApplicationPrivateKey` remains available only
for a previously registered legacy client connecting to an older handshake.

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
  --max-installations-per-user 5 \
  --data /var/lib/scimtest-server/scimtest-server.json \
  --logs
```

Set `SCIMTEST_GITHUB_CLIENT_ID` and `SCIMTEST_GITHUB_CLIENT_SECRET` in the
service environment. The production OAuth callback URL is
`https://admin.example.com/auth/github/callback`.

The default installation limit is five per GitHub account and application.
When an account reaches it, the authorization flow asks the user to explicitly
deactivate one of their existing installations before continuing. Disconnected
installations are ordered by least recent use and preferred over active ones;
choosing an active installation disconnects it immediately. Deactivation
revokes the old installation without deleting its audit record. An approved
setup that has not connected yet can be canceled from the same chooser.
Disconnected, non-revoked installations idle for more than 90 days are pruned
before the limit is checked.

`--behind-proxy` trusts `X-Forwarded-*` only from configured proxy networks.
The default trusted networks are loopback; use `--trusted-proxy-cidrs` when the
proxy runs elsewhere.

The JSON data file contains dashboard sessions, application profiles, remembered
instance names, and the immutable numeric GitHub account ID associated with each
installation. GitHub access tokens and pending enrollment secrets are not
stored. Revoked installation identities remain as durable deny records even if
their public tunnel name is released.

This enrollment protocol requires the matching client and server releases.
Publish the new client first, then deploy the server once the update is
available. A fresh new client cannot enroll with the old server. After the new
server is deployed, old clients cannot complete authorization, and existing
installations without GitHub attribution must update and authorize once before
they reconnect. GitHub-attributed installations then reconnect using their
installation key alone.

Treat every application private key shipped in an older release as compromised.
After the intended legacy installations have upgraded, rotate the profile's
legacy public key to stop all remaining shared-key reconnects.

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
