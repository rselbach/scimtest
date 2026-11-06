use super::*;
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
};

#[path = "shared_http_tests.rs"]
mod http_tests;

#[path = "shared_replacement_tests.rs"]
mod replacement_tests;

#[path = "browser_fixture.rs"]
mod browser_fixture;

struct GoService {
    child: Child,
    response: PathBuf,
    log: PathBuf,
}

impl GoService {
    async fn start(app: &mut Running, fixture: &support::GoFixture) -> Self {
        app.stop().await;
        let request = app.directory.path().join("go-service.json");
        let response = app.directory.path().join("go-service-result.json");
        let log = app.directory.path().join("go-service.log");
        let url = Url::parse(&app.base).unwrap();
        std::fs::write(&request,serde_json::to_vec(&json!({"kind":"service","service":{
            "addr":format!("{}:{}",url.host_str().unwrap(),url.port().unwrap()),
            "domain":app.server.0.config.domain,"dashboard_domain":app.server.0.config.dashboard_domain,
            "scheme":app.server.0.config.public_scheme,"data_path":app.directory.path().join("server.json"),
            "github_token_url":app.server.0.github.token_url,"github_user_url":app.server.0.github.user_url,
            "github_authorize_url":app.server.0.github.authorize_url,
            "max_installations_per_user":app.server.0.config.max_installations_per_user
        }})).unwrap()).unwrap();
        let mut service = Self {
            child: Command::new(&fixture.binary)
                .arg("-test.run=^TestRustHostedContractFixture$")
                .env("SCIMTEST_RUST_HOSTED_CONTRACT", request)
                .env("SCIMTEST_RUST_HOSTED_RESULT", &response)
                .stdout(Stdio::null())
                .stderr(Stdio::from(std::fs::File::create(&log).unwrap()))
                .spawn()
                .unwrap(),
            response,
            log,
        };
        tokio::time::timeout(StdDuration::from_secs(5), async {
            loop {
                assert!(
                    service.child.try_wait().unwrap().is_none(),
                    "{}",
                    std::fs::read_to_string(&service.log).unwrap()
                );
                if app
                    .request(Method::GET, "/ready")
                    .send()
                    .await
                    .is_ok_and(|response| response.status() == StatusCode::OK)
                {
                    break;
                }
                tokio::time::sleep(StdDuration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        service
    }

    async fn stop(&mut self) {
        assert!(
            Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        tokio::time::timeout(StdDuration::from_secs(5), async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    assert!(
                        status.success(),
                        "{}",
                        std::fs::read_to_string(&self.log).unwrap()
                    );
                    break;
                }
                tokio::time::sleep(StdDuration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&std::fs::read(&self.response).unwrap()).unwrap(),
            json!({"stopped":true})
        );
    }
}

impl Drop for GoService {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            self.child.kill().unwrap();
            self.child.wait().unwrap();
        }
    }
}

fn saved(app: &Running) -> Store {
    Store::open(app.directory.path().join("server.json")).unwrap()
}

async fn tunnels(app: &Running, want: u64) {
    tokio::time::timeout(StdDuration::from_secs(5), async {
        loop {
            let value = app
                .request(Method::GET, "/api/metrics")
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();
            if value["tunnels_active"] == want {
                return;
            }
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

async fn finish(app: &mut Running, go: Option<&mut GoService>) {
    if let Some(go) = go {
        go.stop().await;
    }
    app.stop().await;
}

#[tokio::test]
async fn shared_dashboard_oauth_sessions_csrf_and_profile_management() {
    let fixture = support::GoFixture::new();
    for backend in ["Go", "Rust"] {
        println!("Hosted shared dashboard workflow: {backend}");
        let mut app = Running::new(false, 5).await;
        let mut go = if backend == "Go" {
            Some(GoService::start(&mut app, &fixture).await)
        } else {
            None
        };
        for path in ["/dashboard", "/dashboard/tunnels", "/dashboard/app.js"] {
            assert_eq!(
                app.request(Method::GET, path)
                    .send()
                    .await
                    .unwrap()
                    .headers()["location"],
                "/login/github"
            );
        }
        let denied = app
            .request(Method::GET, "/login/github")
            .send()
            .await
            .unwrap();
        assert_eq!(
            app.oauth(denied, "paintball").await.status(),
            StatusCode::FORBIDDEN
        );
        lock(&app.stub.user).login = "rselbach".into();
        for code in ["token-error", "token-redirect"] {
            let start = app
                .request(Method::GET, "/login/github")
                .send()
                .await
                .unwrap();
            assert_eq!(
                app.oauth(start, code).await.status(),
                StatusCode::BAD_GATEWAY
            );
        }
        let start = app
            .request(Method::GET, "/login/github")
            .send()
            .await
            .unwrap();
        let response = app.oauth(start, "paintball").await;
        assert_eq!(response.status(), StatusCode::FOUND);
        let cookie = response_cookie(&response, "scimtest_session");
        let session = saved(&app)
            .session(cookie.split_once('=').unwrap().1)
            .unwrap()
            .unwrap();
        assert!(session.admin);
        let values = [
            ("name", "<script>Troy & Abed</script>"),
            ("public_key", &support::public_key(41)),
            ("routes", "GET /oidc/{slug}/jwks"),
            ("requests_per_minute", "60"),
            ("request_burst", "10"),
            ("concurrent_requests", "4"),
        ];
        assert_eq!(
            app.request(Method::POST, "/dashboard/applications/create")
                .header("cookie", &cookie)
                .form(&values)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(saved(&app).profiles().unwrap().len(), 1);
        let mut create = values.to_vec();
        create.push(("csrf_token", &session.csrf_token));
        assert_eq!(
            app.request(Method::POST, "/dashboard/applications/create")
                .header("cookie", &cookie)
                .form(&create)
                .send()
                .await
                .unwrap()
                .headers()["location"],
            "/dashboard#applications"
        );
        let profile = saved(&app)
            .profiles()
            .unwrap()
            .into_iter()
            .find(|profile| profile.id != app.profile)
            .unwrap();
        let page = app
            .request(Method::GET, "/dashboard")
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(page.headers()["cache-control"], "no-store");
        let html = page.text().await.unwrap();
        assert!(html.contains("&lt;script&gt;Troy &amp; Abed"));
        assert!(!html.contains("<script>Troy & Abed</script>"));
        let update = [
            ("id", profile.id.as_str()),
            ("csrf_token", session.csrf_token.as_str()),
            ("name", "Greendale Study Group"),
            ("public_key", &support::public_key(40)),
            ("routes", "GET,POST /saml/{slug}/sso"),
            ("requests_per_minute", "90"),
            ("request_burst", "20"),
            ("concurrent_requests", "3"),
        ];
        assert_eq!(
            app.request(Method::POST, "/dashboard/applications/update")
                .header("cookie", &cookie)
                .form(&update)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FOUND
        );
        let changed = saved(&app).profile(&profile.id).unwrap().unwrap();
        assert_eq!(changed.settings.name, "Greendale Study Group");
        assert_eq!(changed.settings.public_key, support::public_key(40));
        assert_eq!(
            changed.settings.routes,
            parse_routes("GET,POST /saml/{slug}/sso").unwrap()
        );
        for path in [
            "/logout",
            "/dashboard/applications/create",
            "/dashboard/applications/update",
            "/dashboard/applications/delete",
            "/dashboard/applications/reservations/delete",
            "/dashboard/applications/instances/revoke",
            "/dashboard/tunnels/disconnect",
        ] {
            let response = app
                .request(Method::GET, path)
                .header("cookie", &cookie)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
            assert_eq!(response.headers()["allow"], "POST");
        }
        assert_eq!(
            app.request(Method::POST, "/dashboard/applications/delete")
                .header("cookie", &cookie)
                .form(&[
                    ("id", profile.id.as_str()),
                    ("csrf_token", session.csrf_token.as_str())
                ])
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FOUND
        );
        assert!(saved(&app).profile(&profile.id).unwrap().is_none());
        assert_eq!(
            app.request(Method::POST, "/logout")
                .header("cookie", &cookie)
                .form(&[("csrf_token", session.csrf_token.as_str())])
                .send()
                .await
                .unwrap()
                .headers()["location"],
            "/"
        );
        let expired = app
            .request(Method::GET, "/dashboard")
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(expired.headers()["location"], "/login/github");
        assert!(
            expired.headers()["set-cookie"]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
        finish(&mut app, go.as_mut()).await;
    }
}

#[tokio::test]
async fn shared_installation_confirmation_key_binding_reconnect_and_public_boundaries() {
    let fixture = support::GoFixture::new();
    for backend in ["Go", "Rust"] {
        println!("Hosted shared installation workflow: {backend}");
        let mut app = Running::new(false, 5).await;
        let mut go = if backend == "Go" {
            Some(GoService::start(&mut app, &fixture).await)
        } else {
            None
        };
        let (bad, reply) = app.dial(24, "", "", 25).await;
        closed(reply, "invalid instance signature");
        drop(bad);
        let (socket, reply) = app.dial(24, "legacy-greendale", "", 24).await;
        let required = decode(reply);
        drop(socket);
        assert_eq!(required.kind, "enrollment_required");
        let page = app
            .request(
                Method::GET,
                &format!("/enroll?code={}", required.enrollment_verification_code),
            )
            .send()
            .await
            .unwrap();
        let cookie = response_cookie(&page, "scimtest_enroll_confirm");
        let html = page.text().await.unwrap();
        assert!(html.contains("Match this code"));
        assert!(html.contains(&required.enrollment_verification_code));
        assert!(!html.contains(&required.enrollment_device_code));
        let values = [
            ("code", required.enrollment_verification_code.as_str()),
            ("csrf_token", csrf(&html)),
        ];
        assert_eq!(
            app.request(Method::POST, "/enroll")
                .header("cookie", &cookie)
                .header("origin", "http://citycollege.test")
                .form(&values)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let start = app
            .request(Method::POST, "/enroll")
            .header("cookie", &cookie)
            .header("origin", "http://admin.greendale.test")
            .form(&values)
            .send()
            .await
            .unwrap();
        let approved = app.oauth(start, "paintball").await;
        assert_eq!(approved.status(), StatusCode::OK);
        assert!(
            !approved
                .headers()
                .get_all("set-cookie")
                .iter()
                .any(|value| value.to_str().unwrap().starts_with("scimtest_session="))
        );
        assert_eq!(
            app.poll(&required.enrollment_device_code)
                .await
                .json::<Value>()
                .await
                .unwrap(),
            json!({"status":"approved"})
        );
        let (wrong, reply) = app
            .dial(25, "legacy-greendale", &required.enrollment_device_code, 25)
            .await;
        closed(reply, "does not match");
        drop(wrong);
        let (wrong, reply) = app
            .dial(24, "different-legacy", &required.enrollment_device_code, 24)
            .await;
        closed(reply, "does not match");
        drop(wrong);
        let (socket, reply) = app
            .dial(24, "legacy-greendale", &required.enrollment_device_code, 24)
            .await;
        let registered = decode(reply);
        assert_eq!(registered.kind, "tunnel_registered");
        assert_eq!(registered.github_user_id, 101);
        assert_eq!(registered.github_login, "troy-barnes");
        assert_eq!(
            app.poll(&required.enrollment_device_code).await.status(),
            StatusCode::NOT_FOUND
        );
        let (duplicate, reply) = app.dial(24, "", "", 24).await;
        closed(reply, "already has an active tunnel");
        drop(duplicate);
        for path in [
            "/dashboard",
            "/dashboard/app.js",
            "/login/github",
            "/enroll",
            "/enroll/browser",
            "/enroll/replace",
        ] {
            assert_eq!(
                app.client
                    .get(format!("{}{path}", app.base))
                    .header("host", "public.greendale.test")
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
        for path in [
            "/api/v1/status",
            "/apps/greendale/config.json",
            "/dashboard",
        ] {
            assert_eq!(
                app.client
                    .get(format!(
                        "{}/{}/{path}",
                        app.base,
                        registered.tunnel_id,
                        path = path.trim_start_matches('/')
                    ))
                    .header("host", "public.greendale.test")
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND
            );
        }
        app.disconnect(socket).await;
        tunnels(&app, 0).await;
        let (socket, reply) = app.dial(24, "", "", 24).await;
        assert_eq!(decode(reply).public_url, registered.public_url);
        app.disconnect(socket).await;
        tunnels(&app, 0).await;
        let stored = saved(&app)
            .instance(&app.profile, &app.binding(24, "").instance)
            .unwrap()
            .unwrap();
        assert_eq!(stored.github_user_id, 101);
        assert_eq!(stored.public_key, app.binding(24, "").key);
        let disk = std::fs::read_to_string(app.directory.path().join("server.json")).unwrap();
        for secret in [
            &required.enrollment_device_code,
            &required.enrollment_verification_code,
            "github-secret-stays-on-server",
        ] {
            assert!(!disk.contains(secret));
        }
        finish(&mut app, go.as_mut()).await;
    }
}
