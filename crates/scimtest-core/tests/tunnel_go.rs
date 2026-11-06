use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Client, StatusCode};
use scimtest_core::{
    Store,
    configuration::SettingsPatch,
    model::*,
    runtime::{Options, Runtime},
    tunnel::Config,
};
use serde_json::{Value, json};
use std::process::{Child, Command, Stdio};

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        if self.0.try_wait().unwrap().is_none() {
            self.0.kill().unwrap();
            self.0.wait().unwrap();
        }
    }
}
async fn wait(mut condition: impl AsyncFnMut() -> bool) {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if condition().await {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rust_registers_and_serves_identity_through_the_go_server_and_preserves_its_public_url_on_restart()
 {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("state.db");
    let store = Store::open(&path).unwrap();
    let installation = store.installation_identity().unwrap();
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
                active: true,
                ..Default::default()
            },
        )
        .unwrap();
    let profile = "0123456789abcdef0123456789abcdef";
    let now = chrono::Utc::now();
    let server_state = temporary.path().join("server.json");
    let routes = [
        "/oidc/{slug}/.well-known/openid-configuration",
        "/oidc/{slug}/jwks",
        "/oidc/{slug}/authorize",
        "/oidc/{slug}/token",
        "/oidc/{slug}/userinfo",
        "/saml/{slug}/metadata",
        "/api/v1/status",
        "/apps/{id}/config.json",
        "/inspect/lifecycle/{slug}/saml-logout",
    ]
    .map(|path| json!({"methods":["GET","POST"],"path":path}));
    std::fs::write(&server_state, serde_json::to_vec(&json!({"sessions":{},"application_profiles":{ profile:{"id":profile,"name":"Greendale Rust parity","public_key":installation.public_key(),"routes":routes,"requests_per_minute":600,"request_burst":100,"concurrent_requests":32,"created_at":now,"instances":{installation.fingerprint():{"tunnel_id":"greendale-study-group","public_key":installation.public_key(),"github_user_id":42,"github_login":"troy-barnes","created_at":now,"last_used_at":now}}}}})).unwrap()).unwrap();
    drop(store);
    let binary = temporary.path().join("scimtest-server");
    let output = Command::new("go")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["build", "-o"])
        .arg(&binary)
        .arg("../../cmd/scimtest-server")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let dashboard = format!("localhost:{}", listener.local_addr().unwrap().port());
    drop(listener);
    let _server = Server(
        Command::new(&binary)
            .args(["--addr", &address, "--domain", &address, "--data"])
            .arg(&server_state)
            .args([
                "--dashboard-domain",
                &dashboard,
                "--github-client-id",
                "greendale-test-client",
                "--github-client-secret",
                "greendale-test-secret",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let base = format!("http://{address}");
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    wait(async || client.get(format!("{base}/healthz")).send().await.is_ok()).await;
    let public = format!("{base}/greendale-study-group");
    for _ in 0..2 {
        let runtime = Runtime::start_with_profile(
            Options {
                state_file: Some(path.clone()),
                port: 0,
                ..Default::default()
            },
            &tokio::runtime::Handle::current(),
            Some(Config {
                server_base_url: base.clone(),
                application_profile_id: profile.into(),
                require_account: true,
            }),
        )
        .unwrap();
        wait(async || runtime.tunnel.snapshot().unwrap().connected).await;
        let snapshot = runtime.tunnel.snapshot().unwrap();
        assert_eq!(snapshot.public_url.as_deref(), Some(public.as_str()));
        assert_eq!(snapshot.github_login, "troy-barnes");
        assert_eq!(snapshot.client_ip.as_deref(), Some("127.0.0.1"));
        let discovery: Value = client
            .get(format!(
                "{public}/oidc/greendale/.well-known/openid-configuration"
            ))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(discovery["issuer"], format!("{public}/oidc/greendale"));
        let saml = client
            .get(format!("{public}/saml/greendale/metadata"))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(saml.contains(&format!("{public}/saml/greendale/sso")));
        let authorization = client
            .post(format!("{public}/oidc/greendale/authorize"))
            .form(&[
                ("client_id", "study-group"),
                ("response_type", "code"),
                ("redirect_uri", "https://greendale.example/callback"),
                ("scope", "openid profile email"),
                ("user_id", &user.id),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(authorization.status(), StatusCode::FOUND);
        let redirect =
            url::Url::parse(authorization.headers()["location"].to_str().unwrap()).unwrap();
        let code = redirect
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned();
        let token: Value = client
            .post(format!("{public}/oidc/greendale/token"))
            .basic_auth(
                "study-group",
                Some(&environment.settings.oidc_client_secret),
            )
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "https://greendale.example/callback"),
            ])
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let claims: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(
                    token["id_token"]
                        .as_str()
                        .unwrap()
                        .split('.')
                        .nth(1)
                        .unwrap(),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(claims["iss"], format!("{public}/oidc/greendale"));
        let userinfo: Value = client
            .get(format!("{public}/oidc/greendale/userinfo"))
            .bearer_auth(token["access_token"].as_str().unwrap())
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(userinfo["email"], "troy@greendale.edu");
        for suffix in [
            "/api/v1/status",
            "/apps/greendale/config.json",
            "/inspect/lifecycle/greendale/saml-logout",
        ] {
            assert_eq!(
                client
                    .get(format!("{public}{suffix}"))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
        runtime.shutdown().await.unwrap();
        wait(async || {
            client
                .get(format!("{public}/oidc/greendale/jwks"))
                .send()
                .await
                .unwrap()
                .status()
                == StatusCode::NOT_FOUND
        })
        .await;
    }
    let pending = Runtime::start_with_profile(
        Options {
            state_file: Some(temporary.path().join("new-installation.db")),
            port: 0,
            ..Default::default()
        },
        &tokio::runtime::Handle::current(),
        Some(Config {
            server_base_url: base,
            application_profile_id: profile.into(),
            require_account: true,
        }),
    )
    .unwrap();
    wait(async || pending.tunnel.snapshot().unwrap().state() == "authorizing").await;
    let snapshot = pending.tunnel.snapshot().unwrap();
    assert!(!pending.tunnel.unlocked().unwrap());
    assert!(!snapshot.enrollment_code.is_empty());
    assert!(snapshot.enrollment_url.contains("presentation=desktop"));
    assert!(
        !pending
            .tunnel
            .account()
            .unwrap()
            .to_string()
            .contains("enrollment_device_code")
    );
    let handoff = pending.tunnel.authorization_url().unwrap();
    assert!(handoff.starts_with(&format!("http://{dashboard}/enroll/browser?handoff=")));
    let response = client.get(handoff).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        response.headers()["location"]
            .to_str()
            .unwrap()
            .starts_with("https://github.com/login/oauth/authorize?")
    );
    assert_eq!(pending.tunnel.snapshot().unwrap().state(), "authorizing");
    pending.shutdown().await.unwrap();
}
