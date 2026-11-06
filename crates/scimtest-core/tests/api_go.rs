use reqwest::{Client, Method};
use scimtest_core::{
    Store,
    configuration::SettingsPatch,
    model::*,
    runtime::{Options, Runtime},
};
use serde_json::{Value, json};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
};

struct GoApp {
    child: Child,
    base: String,
    token: String,
}
impl Drop for GoApp {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            self.child.kill().unwrap();
            self.child.wait().unwrap();
        }
    }
}
impl GoApp {
    async fn start(directory: &Path, client: &Client) -> Self {
        let binary = directory.join("scimtest-go");
        let output = Command::new("go")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args(["build", "-o"])
            .arg(&binary)
            .arg("../../cmd/scimtest")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        drop(listener);
        let child = Command::new(binary)
            .args(["--no-open", "--port", &port, "--state-file"])
            .arg(directory.join("go.db"))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut app = Self {
            child,
            base: String::new(),
            token: String::new(),
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if let Ok(bytes) = std::fs::read(directory.join("go.db.lock"))
                    && let Ok(metadata) = serde_json::from_slice::<Value>(&bytes)
                    && let (Some(base), Some(token)) =
                        (metadata["url"].as_str(), metadata["token"].as_str())
                    && client
                        .get(format!("{base}/api/v1/status"))
                        .header("X-Scimtest-Instance-Token", token)
                        .send()
                        .await
                        .is_ok()
                {
                    app.base = base.into();
                    app.token = token.into();
                    break;
                }
                assert!(
                    app.child.try_wait().unwrap().is_none(),
                    "Go runner exited during startup"
                );
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        app
    }
}
async fn request(
    client: &Client,
    base: &str,
    token: &str,
    method: &str,
    path: &str,
) -> (u16, Value) {
    let response = client
        .request(method.parse::<Method>().unwrap(), format!("{base}{path}"))
        .header("X-Scimtest-Instance-Token", token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let status = response.status().as_u16();
    let bytes = response.bytes().await.unwrap();
    let mut body: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("{path}: {error}: {}", String::from_utf8_lossy(&bytes)))
    };
    normalize(&mut body, base);
    (status, body)
}

struct Case<'a> {
    name: &'a str,
    method: &'a str,
    path: &'a str,
    body: &'a str,
    headers: Vec<(&'a str, &'a str)>,
}
async fn boundary(
    client: &Client,
    base: &str,
    token: &str,
    case: &Case<'_>,
) -> (u16, String, Value) {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("X-Scimtest-Instance-Token", token.parse().unwrap());
    headers.insert("Content-Type", "application/json".parse().unwrap());
    for (name, value) in &case.headers {
        headers.insert(
            name.parse::<reqwest::header::HeaderName>().unwrap(),
            value.parse().unwrap(),
        );
    }
    let request = client
        .request(
            case.method.parse::<Method>().unwrap(),
            format!("{base}{}", case.path),
        )
        .headers(headers)
        .body(case.body.to_owned());
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let allow = response
        .headers()
        .get("allow")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let bytes = response.bytes().await.unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, allow, body)
}

fn catalog_compatible(want: &Value, got: &Value) {
    assert_eq!(want["version"], got["version"]);
    let want = want["routes"].as_array().unwrap();
    let got = got["routes"].as_array().unwrap();
    assert_eq!(want.len(), got.len());
    for route in want {
        let found = got
            .iter()
            .find(|candidate| {
                candidate["path"] == route["path"] && candidate["method"] == route["method"]
            })
            .unwrap_or_else(|| panic!("missing route: {route}"));
        for field in route["fields"].as_array().into_iter().flatten() {
            assert!(
                found["fields"]
                    .as_array()
                    .is_some_and(|fields| fields.contains(field)),
                "missing field {field} on {route}"
            );
        }
    }
}
fn normalize(value: &mut Value, base: &str) {
    match value {
        Value::String(text) => *text = text.replace(base, "http://greendale.local"),
        Value::Array(items) => {
            for item in items {
                normalize(item, base);
            }
        }
        Value::Object(fields) => {
            for item in fields.values_mut() {
                normalize(item, base);
            }
        }
        _ => {}
    }
}
async fn directory_snapshot(client: &Client, base: &str, token: &str, path: &str) -> Value {
    let mut users = request(client, base, token, "GET", &format!("{path}/users"))
        .await
        .1;
    let mut groups = request(client, base, token, "GET", &format!("{path}/groups"))
        .await
        .1;
    let labels = users
        .as_array()
        .unwrap()
        .iter()
        .map(|user| {
            (
                user["id"].as_str().unwrap().to_owned(),
                user["username"].as_str().unwrap().to_owned(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    for user in users.as_array_mut().unwrap() {
        user["id"] = json!(labels[user["id"].as_str().unwrap()]);
        if let Some(manager) = user["manager_id"]
            .as_str()
            .filter(|value| !value.is_empty())
        {
            user["manager_id"] = json!(labels[manager]);
        }
    }
    for group in groups.as_array_mut().unwrap() {
        group["id"] = group["display_name"].clone();
        if let Some(members) = group["member_ids"].as_array_mut() {
            for member in members {
                *member = json!(labels[member.as_str().unwrap()]);
            }
        }
    }
    json!({"users":users,"groups":groups})
}

#[tokio::test]
async fn local_api_contract_matches_the_go_runner() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("rust.db");
    let store = Store::open(&path).unwrap();
    let environment = store
        .create_environment(EnvironmentInput {
            name: "Greendale".into(),
            settings: SettingsPatch {
                oidc_enabled: Some(true),
                oidc_client_id: Some("study-group".into()),
                oidc_redirect_uris: Some(vec!["https://greendale.example/callback".into()]),
                saml_enabled: Some(true),
                saml_entity_id: Some("urn:greendale:sp".into()),
                saml_acs_url: Some("https://greendale.example/acs".into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
    let user = store
        .create_user(
            &environment.id,
            UserInput {
                given_name: "Troy".into(),
                family_name: "Barnes".into(),
                email: "troy@greendale.edu".into(),
                ..Default::default()
            },
        )
        .unwrap();
    let group = store
        .create_group(
            &environment.id,
            GroupInput {
                display_name: "Study Group".into(),
                member_ids: vec![user.id.clone()],
            },
        )
        .unwrap();
    let empty = store
        .create_environment(EnvironmentInput {
            name: "City College".into(),
            ..Default::default()
        })
        .unwrap();
    store
        .create_group(
            &empty.id,
            GroupInput {
                display_name: "Glee Club".into(),
                ..Default::default()
            },
        )
        .unwrap();
    store.active_signing_key(&environment.id).unwrap();
    drop(store);
    std::fs::copy(&path, temporary.path().join("go.db")).unwrap();
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let go = GoApp::start(temporary.path(), &client).await;
    let rust = Runtime::start_with_profile(
        Options {
            state_file: Some(path),
            port: 0,
            ..Default::default()
        },
        &tokio::runtime::Handle::current(),
        None,
    )
    .unwrap();
    let metadata: Value =
        serde_json::from_slice(&std::fs::read(temporary.path().join("rust.db.lock")).unwrap())
            .unwrap();
    let token = metadata["token"].as_str().unwrap();
    let base = format!("/api/v1/environments/{}", environment.id);
    let mut paths = vec![
        "/api/v1/status".into(),
        "/api/v1/config".into(),
        "/api/v1/account".into(),
        "/api/v1/tunnel".into(),
        "/api/v1/environments".into(),
        base.clone(),
        format!("{base}/users"),
        format!("{base}/users/{}", user.id),
        format!("{base}/users/{}/operations", user.id),
        format!("{base}/groups"),
        format!("{base}/groups/{}", group.id),
        format!("{base}/groups/{}/operations", group.id),
        format!("{base}/connection"),
        format!("{base}/signing-keys"),
        format!("{base}/sync/status"),
        format!("{base}/faults"),
        format!("{base}/flows"),
        format!("{base}/inspections/oidc"),
        format!("{base}/inspections/saml"),
        format!("{base}/scenarios"),
        format!("{base}/lifecycle"),
    ];
    for suffix in [
        "",
        "/users",
        "/groups",
        "/signing-keys",
        "/faults",
        "/flows",
        "/oidc/tokens",
        "/saml/logouts",
        "/sessions",
        "/inspections/oidc",
        "/inspections/saml",
        "/scenarios",
        "/lifecycle",
        "/sync/status",
        "/sync/plan",
        "/sync/trace",
    ] {
        paths.push(format!("/api/v1/environments/{}{suffix}", empty.id));
    }
    let mut failures = Vec::new();
    for path in paths {
        let want = request(&client, &go.base, &go.token, "GET", &path).await;
        let got = request(&client, &rust.url, token, "GET", &path).await;
        if got != want {
            failures.push(json!({"path":path,"go":want,"rust":got}));
        }
    }
    for case in [
        Case {
            name: "catalog slash",
            method: "GET",
            path: "/api/v1/",
            body: "",
            headers: vec![],
        },
        Case {
            name: "catalog method",
            method: "POST",
            path: "/api/v1/",
            body: "",
            headers: vec![],
        },
        Case {
            name: "HEAD is not GET",
            method: "HEAD",
            path: "/api/v1/status",
            body: "",
            headers: vec![],
        },
        Case {
            name: "method allow",
            method: "PUT",
            path: "/api/v1/environments",
            body: "{}",
            headers: vec![],
        },
        Case {
            name: "missing token",
            method: "GET",
            path: "/api/v1/status",
            body: "",
            headers: vec![("X-Scimtest-Instance-Token", "")],
        },
        Case {
            name: "host boundary",
            method: "GET",
            path: "/api/v1/status",
            body: "",
            headers: vec![("Host", "citycollege.example")],
        },
        Case {
            name: "cross origin before auth",
            method: "PATCH",
            path: &base,
            body: "{}",
            headers: vec![
                ("Origin", "https://citycollege.example"),
                ("X-Scimtest-Instance-Token", ""),
            ],
        },
        Case {
            name: "fetch site",
            method: "PATCH",
            path: &base,
            body: "{}",
            headers: vec![("Sec-Fetch-Site", "cross-site")],
        },
        Case {
            name: "unsupported body type",
            method: "PATCH",
            path: &base,
            body: "{}",
            headers: vec![("Content-Type", "text/plain")],
        },
        Case {
            name: "array body",
            method: "PATCH",
            path: &base,
            body: "[]",
            headers: vec![],
        },
        Case {
            name: "null field",
            method: "PATCH",
            path: &base,
            body: "{\"name\":null}",
            headers: vec![],
        },
        Case {
            name: "malformed body",
            method: "PATCH",
            path: &base,
            body: "{\"name\":",
            headers: vec![],
        },
        Case {
            name: "unknown field",
            method: "PATCH",
            path: &base,
            body: "{\"unknown\":true}",
            headers: vec![],
        },
        Case {
            name: "unknown route",
            method: "GET",
            path: "/api/v1/unknown",
            body: "",
            headers: vec![],
        },
        Case {
            name: "case insensitive duplicate field order",
            method: "PATCH",
            path: &base,
            body: r#"{"name":"City College","NAME":"Greendale Revised"}"#,
            headers: vec![],
        },
        Case {
            name: "missing environment",
            method: "GET",
            path: "/api/v1/environments/missing/users",
            body: "",
            headers: vec![],
        },
    ] {
        let mut want = boundary(&client, &go.base, &go.token, &case).await;
        let mut got = boundary(&client, &rust.url, token, &case).await;
        if case.name == "catalog slash" && want.0 == 200 && got.0 == 200 {
            catalog_compatible(&want.2, &got.2);
            want.2 = Value::Null;
            got.2 = Value::Null;
        }
        if want != got {
            failures.push(json!({"case":case.name,"go":want,"rust":got}));
        }
    }
    let user_path = format!("{base}/users/{}", user.id);
    let group_path = format!("{base}/groups/{}", group.id);
    for (name, method, path, body) in [
        (
            "reject an empty given name atomically",
            "PATCH",
            user_path.clone(),
            r#"{"given_name":"","active":false}"#,
        ),
        (
            "clear group membership",
            "PATCH",
            group_path.clone(),
            r#"{"member_ids":[]}"#,
        ),
        ("delete group", "DELETE", group_path.clone(), ""),
        (
            "restore missing group",
            "POST",
            format!("{group_path}/restore"),
            "",
        ),
        (
            "create generated users",
            "POST",
            format!("{base}/tools/create-users"),
            r#"{"count":3,"email_domain":"greendale.edu"}"#,
        ),
        (
            "deactivate everyone",
            "POST",
            format!("{base}/tools/deactivate-all"),
            "{}",
        ),
        (
            "activate everyone",
            "POST",
            format!("{base}/tools/activate-all"),
            "{}",
        ),
        ("delete user", "DELETE", user_path, ""),
        (
            "clear local directory",
            "POST",
            format!("{base}/tools/clear-local"),
            "{}",
        ),
    ] {
        let case = Case {
            name,
            method,
            path: &path,
            body,
            headers: vec![],
        };
        let want = boundary(&client, &go.base, &go.token, &case).await;
        let got = boundary(&client, &rust.url, token, &case).await;
        if want != got {
            failures.push(json!({"case":name,"go":want,"rust":got}));
        }
    }
    for (name, path, body) in [
        (
            "create bare environment",
            "/api/v1/environments".into(),
            r#"{"name":"Greendale Satellite"}"#,
        ),
        (
            "create OIDC environment",
            "/api/v1/environments".into(),
            r#"{"name":"Student Portal","oidc_enabled":true,"oidc_client_id":"student-portal","oidc_client_secret":"greendale-confidential-test-secret","oidc_redirect_uris":["https://greendale.example/callback"]}"#,
        ),
        (
            "create public client",
            "/api/v1/environments".into(),
            r#"{"name":"Mobile Study Group","oidc_enabled":true,"oidc_public_client":true,"oidc_redirect_uris":["https://greendale.example/callback"]}"#,
        ),
        (
            "create SAML environment",
            "/api/v1/environments".into(),
            r#"{"name":"Greendale SAML","saml_enabled":true,"saml_entity_id":"urn:greendale:sp","saml_acs_url":"https://greendale.example/acs"}"#,
        ),
        (
            "create user with omitted family name",
            format!("{base}/users"),
            r#"{"given_name":"Abed","email":"abed@greendale.edu"}"#,
        ),
        (
            "create existing sample email with a different username",
            format!("{base}/users"),
            r#"{"given_name":"Troy","email":"troy.barnes@greendale.edu","username":"air-conditioning-trainee"}"#,
        ),
        (
            "create group with omitted members",
            format!("{base}/groups"),
            r#"{"display_name":"Blanket Fort"}"#,
        ),
        (
            "create group with empty members",
            format!("{base}/groups"),
            r#"{"display_name":"Pillow Fort","member_ids":[]}"#,
        ),
    ] {
        let case = Case {
            name,
            method: "POST",
            path: &path,
            body,
            headers: vec![],
        };
        let mut want = boundary(&client, &go.base, &go.token, &case).await;
        let mut got = boundary(&client, &rust.url, token, &case).await;
        for response in [&mut want, &mut got] {
            assert_eq!(response.0, 201, "{name}: {response:?}");
            assert!(response.2["id"].as_str().is_some_and(|id| !id.is_empty()));
            response.2["id"] = json!("generated-id");
        }
        if want != got {
            failures.push(json!({"case":name,"go":want,"rust":got}));
        }
    }
    for _ in 0..2 {
        let path = format!("{base}/tools/seed-sample");
        let case = Case {
            name: "sample seed",
            method: "POST",
            path: &path,
            body: "{}",
            headers: vec![],
        };
        let want = boundary(&client, &go.base, &go.token, &case).await;
        let got = boundary(&client, &rust.url, token, &case).await;
        if want != got {
            failures.push(json!({"case":"sample seeding","go":want,"rust":got}));
        }
    }
    let want = directory_snapshot(&client, &go.base, &go.token, &base).await;
    let got = directory_snapshot(&client, &rust.url, token, &base).await;
    if want != got {
        failures.push(json!({"case":"seeded directory with email collisions and manager memberships","go":want,"rust":got}));
    }
    let handed = scimtest_core::runtime::Runtime::launch(
        Options {
            state_file: Some(temporary.path().join("go.db")),
            no_open: true,
            ..Default::default()
        },
        &tokio::runtime::Handle::current(),
    )
    .await
    .unwrap();
    match handed {
        scimtest_core::runtime::Launch::Existing(instance) => assert_eq!(instance.url, go.base),
        _ => panic!("Rust must recognize the Go runner's live lease"),
    }
    rust.shutdown().await.unwrap();
    assert!(
        failures.is_empty(),
        "{}",
        serde_json::to_string_pretty(&failures).unwrap()
    );
}
