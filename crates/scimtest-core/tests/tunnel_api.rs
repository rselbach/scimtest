#[path = "tunnel/server.rs"]
mod server;
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{Client, StatusCode};
use scimtest_core::{
    configuration::{GlobalConfigPatch, SettingsPatch},
    model::*,
    runtime::{Options, Runtime},
    tunnel::Config,
};
use serde_json::{Value, json};
use server::{Command, Server};
use std::sync::atomic::Ordering;

struct App {
    runtime: Runtime,
    client: Client,
    token: String,
    _temporary: tempfile::TempDir,
}
impl App {
    fn new(server: Option<&Server>, required: bool) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let state_file = temporary.path().join("state.db");
        let runtime = Runtime::start_with_profile(
            Options {
                state_file: Some(state_file),
                port: 0,
                ..Default::default()
            },
            &tokio::runtime::Handle::current(),
            server.map(|server| Config {
                server_base_url: server.shared.base.clone(),
                application_profile_id: "0123456789abcdef0123456789abcdef".into(),
                require_account: required,
            }),
        )
        .unwrap();
        let metadata: Value =
            serde_json::from_slice(&std::fs::read(temporary.path().join("state.db.lock")).unwrap())
                .unwrap();
        Self {
            runtime,
            token: metadata["token"].as_str().unwrap().into(),
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            _temporary: temporary,
        }
    }
    async fn request(&self, method: &str, path: &str) -> (StatusCode, Value) {
        let response = self
            .client
            .request(
                method.parse::<reqwest::Method>().unwrap(),
                format!("{}{path}", self.runtime.url),
            )
            .header("X-Scimtest-Instance-Token", &self.token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        let status = response.status();
        let bytes = response.bytes().await.unwrap();
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, body)
    }
    async fn wait(&self, predicate: impl Fn(&scimtest_core::tunnel::Snapshot) -> bool) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if predicate(&self.runtime.tunnel.snapshot().unwrap()) {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
}
async fn public(
    server: &mut Server,
    method: &str,
    path: &str,
    visitor: &str,
) -> (u64, Value, String) {
    server.send(json!({"type":"request","stream_id":7,"method":method,"path":path,"header":{"X-Forwarded-For":[visitor]}}));
    let response = server.receive().await;
    assert!(response.get("error").is_none(), "{response}");
    let body = String::from_utf8(
        STANDARD
            .decode(response["body"].as_str().unwrap_or_default())
            .unwrap(),
    )
    .unwrap();
    (response["status_code"].as_u64().unwrap(), response, body)
}

#[tokio::test]
async fn account_gate_tracks_enrollment_revocation_retry_and_account_switching() {
    let server = Server::new(true).await;
    let app = App::new(Some(&server), true);
    app.wait(|snapshot| snapshot.state() == "authorizing").await;
    for (method, path) in [
        ("GET", "/api/v1/config"),
        ("POST", "/api/v1/environments"),
        ("POST", "/api/v1/account/logout"),
        ("GET", "/apps/greendale/config.json"),
        ("GET", "/oidc/greendale/.well-known/openid-configuration"),
        ("GET", "/saml/greendale/metadata"),
    ] {
        let (status, body) = app.request(method, path).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(body["error"], "GitHub account sign-in is required");
    }
    for (method, path) in [
        ("GET", "/api/v1"),
        ("GET", "/api/v1/status"),
        ("GET", "/api/v1/account"),
        ("POST", "/api/v1/account/start"),
        ("POST", "/api/v1/account/retry"),
        ("GET", "/api/v1/tunnel"),
        ("POST", "/api/v1/tunnel/retry"),
    ] {
        assert_eq!(app.request(method, path).await.0, StatusCode::OK, "{path}");
    }
    assert_eq!(
        app.request("GET", "/-/ready").await.0,
        StatusCode::NO_CONTENT
    );
    let status = app.request("GET", "/api/v1/status").await.1;
    assert_eq!(status["locked"], true);
    assert_eq!(
        status["tunnel"],
        json!({"supported":true,"starting":true,"connected":false,"error":""})
    );
    let account = app.request("POST", "/api/v1/account/start").await.1;
    assert_eq!(account["state"], "authorizing");
    assert!(!account.to_string().contains("greendale-device-secret"));
    let root = app.client.get(&app.runtime.url).send().await.unwrap();
    assert_eq!(root.status(), StatusCode::OK);
    assert!(root.text().await.unwrap().contains("Continue with GitHub"));
    assert_eq!(
        app.client
            .get(format!("{}/api/v1/account", app.runtime.url))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.client
            .get(format!("{}/api/v1/account", app.runtime.url))
            .header("host", "citycollege.example")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::MISDIRECTED_REQUEST
    );
    server.shared.approved.store(true, Ordering::SeqCst);
    app.wait(|snapshot| snapshot.connected).await;
    assert_eq!(app.request("GET", "/api/v1/config").await.0, StatusCode::OK);
    assert_eq!(
        app.request("GET", "/api/v1/status").await.1["locked"],
        false
    );
    assert_eq!(
        app.request("GET", "/api/v1/account").await.1["login"],
        "troy-barnes"
    );
    server
        .commands
        .send(Command::Close(1008, "installation revoked".into()))
        .unwrap();
    app.wait(|snapshot| snapshot.retry_available).await;
    assert_eq!(
        app.request("GET", "/api/v1/config").await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.request("POST", "/api/v1/tunnel/retry").await.0,
        StatusCode::OK
    );
    app.wait(|snapshot| snapshot.connected).await;
    let fingerprint = app
        .runtime
        .store
        .installation_identity()
        .unwrap()
        .fingerprint();
    server.shared.approved.store(false, Ordering::SeqCst);
    *server.shared.login.lock().unwrap() = "abed-nadir".into();
    let (status, body) = app.request("POST", "/api/v1/account/logout").await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(body["state"], "connected");
    assert_ne!(
        app.runtime
            .store
            .installation_identity()
            .unwrap()
            .fingerprint(),
        fingerprint
    );
    app.wait(|snapshot| snapshot.state() == "authorizing").await;
    server.shared.approved.store(true, Ordering::SeqCst);
    app.wait(|snapshot| snapshot.connected).await;
    assert_eq!(
        app.request("GET", "/api/v1/account").await.1["login"],
        "abed-nadir"
    );
    let url = app.runtime.url.clone();
    let tunnel = app.runtime.tunnel.clone();
    app.runtime.shutdown().await.unwrap();
    assert!(!tunnel.unlocked().unwrap());
    assert!(Client::new().get(url).send().await.is_err());
}

#[tokio::test]
async fn public_listener_strips_only_its_prefix_limits_choosers_and_keeps_admin_routes_local() {
    let mut server = Server::new(false).await;
    let app = App::new(Some(&server), true);
    let store = &app.runtime.store;
    let environment = store
        .create_environment(EnvironmentInput {
            name: "Greendale".into(),
            settings: SettingsPatch {
                oidc_enabled: Some(true),
                oidc_client_id: Some("study-group".into()),
                oidc_redirect_uris: Some(vec!["https://greendale.example/callback".into()]),
                allow_any_oidc_redirect: Some(true),
                saml_enabled: Some(true),
                saml_entity_id: Some("urn:greendale:sp".into()),
                saml_acs_url: Some("https://greendale.example/acs".into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
    store
        .update_global_config(&GlobalConfigPatch {
            idp_base_url: Some("https://identity.citycollege.example".into()),
            ..Default::default()
        })
        .unwrap();
    store.active_signing_key(&environment.id).unwrap();
    store.seed_sample(&environment.id).unwrap();
    app.wait(|snapshot| snapshot.connected).await;
    let (status, _, body) = public(
        &mut server,
        "GET",
        "/greendale/oidc/greendale/.well-known/openid-configuration",
        "",
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["issuer"],
        "https://scimtest.example/greendale/oidc/greendale"
    );
    let (status, _, body) =
        public(&mut server, "GET", "/greendale/saml/greendale/metadata", "").await;
    assert_eq!(status, 200);
    assert!(body.contains("https://scimtest.example/greendale/saml/greendale/sso"));
    for path in [
        "/oidc/greendale/jwks",
        "/greendale-other/oidc/greendale/jwks",
        "/greendale/api/v1/status",
        "/greendale/api/v1/account",
        "/greendale/-/activate",
        "/greendale/apps/greendale/config.json",
        "/greendale/?tab=lifecycle",
        "/greendale/inspect/lifecycle/greendale/saml-logout",
        "/greendale/inspect/oidc/greendale",
        "/greendale/inspect/oidc/greendale/playground",
        "/greendale/inspect/oidc/greendale/playground/callback",
        "/greendale/inspect/oidc/greendale/playground/refresh",
        "/greendale/saml/greendale/continue/greendale-ticket",
    ] {
        assert_eq!(
            public(&mut server, "GET", path, "203.0.113.7").await.0,
            404,
            "{path}"
        );
    }
    store
        .update_environment(
            &environment.id,
            EnvironmentPatch {
                settings: SettingsPatch {
                    oidc_client_secret: Some("greendale-secret".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    let response = app
        .client
        .get(format!(
            "{}/inspect/oidc/greendale/playground",
            app.runtime.url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let location = url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
    assert_eq!(location.origin().ascii_serialization(), app.runtime.url);
    assert_eq!(location.path(), "/oidc/greendale/authorize");
    assert!(
        location
            .query_pairs()
            .any(|(key, value)| key == "redirect_uri"
                && value
                    == format!(
                        "{}/inspect/oidc/greendale/playground/callback",
                        app.runtime.url
                    ))
    );
    let authorize = "/oidc/greendale/authorize?client_id=study-group&response_type=code&scope=openid&redirect_uri=https%3A%2F%2Fgreendale.example%2Fcallback";
    for visitor in ["", "203.0.113.8", "invalid", "203.0.113.8, 203.0.113.7"] {
        assert_eq!(
            public(
                &mut server,
                "GET",
                &format!("/greendale{authorize}"),
                visitor
            )
            .await
            .0,
            403
        );
        assert_eq!(
            public(&mut server, "GET", "/greendale/saml/greendale/sso", visitor)
                .await
                .0,
            403
        );
    }
    for visitor in [
        "203.0.113.7",
        "::ffff:203.0.113.7",
        "203.0.113.7, 192.0.2.3",
    ] {
        let (status, _, body) = public(
            &mut server,
            "GET",
            &format!("/greendale{authorize}"),
            visitor,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        assert!(body.contains("id=\"chooser-form\""));
        assert!(body.contains("method=\"post\""));
        assert!(body.contains("action=\"\""));
    }
    let arbitrary = authorize.replace("greendale.example", "citycollege.example");
    assert_eq!(
        app.client
            .get(format!("{}{arbitrary}", app.runtime.url))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        public(
            &mut server,
            "GET",
            &format!("/greendale{arbitrary}"),
            "203.0.113.7"
        )
        .await
        .0,
        400
    );
    let config = app
        .request(
            "GET",
            &format!("/api/v1/environments/{}/connection", environment.id),
        )
        .await
        .1;
    assert_eq!(
        config["oidc"]["issuer"],
        "https://scimtest.example/greendale/oidc/greendale"
    );
    let traffic = app.runtime.identity.diagnostics().snapshot().unwrap();
    assert!(
        serde_json::to_string(&traffic)
            .unwrap()
            .contains("/greendale/oidc/greendale/authorize?")
    );
    app.runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn headless_and_source_builds_remain_usable_without_an_enrolled_account() {
    let server = Server::new(true).await;
    let headless = App::new(Some(&server), false);
    headless
        .wait(|snapshot| snapshot.state() == "authorizing")
        .await;
    assert_eq!(
        headless.request("GET", "/api/v1/config").await.0,
        StatusCode::OK
    );
    assert_eq!(
        headless.request("GET", "/api/v1/status").await.1["locked"],
        false
    );
    for path in ["/api/v1/account/start", "/api/v1/account/logout"] {
        assert_eq!(
            headless.request("POST", path).await,
            (
                StatusCode::NOT_FOUND,
                json!({"error":"account sign-in is not enabled"})
            )
        );
    }
    headless.runtime.shutdown().await.unwrap();
    let source = App::new(None, false);
    assert_eq!(
        source.request("GET", "/api/v1/config").await.0,
        StatusCode::OK
    );
    assert_eq!(
        source.request("GET", "/api/v1/account").await.1["state"],
        "unavailable"
    );
    assert_eq!(
        source.request("GET", "/api/v1/tunnel").await.1,
        json!({"supported":false,"starting":false,"connected":false,"retry_available":false,"error":"","enrollment_url":"","enrollment_code":""})
    );
    source.runtime.shutdown().await.unwrap();
}
