# Automate a local instance

Use the local API to create an environment and a user, complete an OIDC
authorization-code flow, and inspect the result. The example uses Python's
standard library. It needs no client package.

## Start an isolated instance

Run the source application with a separate state file:

```sh
go run ./cmd/scimtest --no-open --state-file /tmp/greendale-agent/state.db
```

Keep that process running. In another terminal, run the example below. The
application writes its URL and API token to `state.db.lock`. Reading this file
avoids guessing the port, which can change between installations.

For an already running desktop app, replace the path with its state file.
The default on macOS is
`~/Library/Application Support/scimtest/state.db`. On Linux it is
`${XDG_CONFIG_HOME:-$HOME/.config}/scimtest/state.db`. A desktop build still
requires its normal GitHub account sign-in. `GET /api/v1/account` reports its
authorization state and enrollment details.

## Create a directory and sign in

Run this against the isolated instance:

```sh
python3 - /tmp/greendale-agent/state.db <<'PY'
import json
from pathlib import Path
import sys
from urllib.parse import urlencode
from urllib.request import Request, urlopen

state_file = Path(sys.argv[1]).expanduser().resolve()
instance = json.loads(Path(str(state_file) + ".lock").read_text())
base_url = instance["url"].rstrip("/")

def api(method, path, body=None):
    request = Request(
        base_url + "/api/v1" + path,
        data=None if body is None else json.dumps(body).encode(),
        method=method,
        headers={
            "Content-Type": "application/json",
            "X-Scimtest-Instance-Token": instance["token"],
        },
    )
    with urlopen(request, timeout=30) as response:
        return json.load(response)

environment = api("POST", "/environments", {
    "name": "Greendale Agent",
    "slug": "greendale-agent",
    "oidc_enabled": True,
    "oidc_client_id": "greendale-client",
    "oidc_redirect_uris": ["http://127.0.0.1:9999/callback"],
})
env = "/environments/" + environment["id"]
user = api("POST", env + "/users", {
    "given_name": "Troy",
    "family_name": "Barnes",
    "email": "troy@greendale.edu",
})
connection = api("GET", env + "/connection")["oidc"]
authorization = api("POST", env + "/oidc/authorize", {
    "user_id": user["id"],
    "response_type": "code",
    "client_id": connection["client_id"],
    "redirect_uri": "http://127.0.0.1:9999/callback",
    "scope": "openid profile email",
    "state": "greendale-test",
    "nonce": "study-group",
})
token_request = Request(
    connection["token_url"],
    data=urlencode({
        "grant_type": "authorization_code",
        "code": authorization["code"],
        "redirect_uri": "http://127.0.0.1:9999/callback",
        "client_id": connection["client_id"],
        "client_secret": connection["client_secret"],
    }).encode(),
    headers={"Content-Type": "application/x-www-form-urlencoded"},
)
with urlopen(token_request, timeout=30) as response:
    tokens = json.load(response)
userinfo_request = Request(connection["userinfo_url"], headers={
    "Authorization": "Bearer " + tokens["access_token"],
})
with urlopen(userinfo_request, timeout=30) as response:
    userinfo = json.load(response)
assert userinfo["email"] == "troy@greendale.edu", userinfo
print(json.dumps({
    "environment_id": environment["id"],
    "user_id": user["id"],
    "email": userinfo["email"],
    "flow_events": len(api("GET", env + "/flows")),
}, indent=2))
PY
```

The output includes the new environment ID, user ID, Troy's email, and the
number of recorded flow events. No callback server is needed for this test
because the API returns the authorization code directly.

For a single-call test, use
`api("POST", env + "/oidc/playground", {"user_id": user["id"]})`. The response
contains decoded ID-token claims, userinfo, and the status of each protocol
step. An optional `faults` object lets the same call test failures.

To run another test against this environment, reuse its ID. To create another
environment, choose a different slug.

## Discover other operations

Use the same `api` function with `GET /` to retrieve the operation catalog.
The [API reference](api.md) describes requests, update behavior, sync polling,
faults, and backups.

Read the lock file again after the application restarts. Each running instance
has its own token. The API token stays on the loopback connection; OIDC and
SCIM credentials are separate.
