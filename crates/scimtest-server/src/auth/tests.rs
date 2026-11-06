use super::*;
use crate::{
    Config, Server,
    application::{ApplicationSettings, parse_instance_key, parse_routes},
    enrollment::{Binding, hash},
    store::{EnrollmentActor, Store},
};
use axum::{Router, body::Body, extract::State as AxumState, response::IntoResponse};
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use reqwest::{Client, Method};
use scimtest_protocol::{Message, instance_challenge_payload};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite};
use tokio_util::sync::CancellationToken;

#[path = "../../tests/support/mod.rs"]
mod support;

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

#[derive(Clone)]
struct GitHubStub {
    user: Arc<Mutex<GitHubUser>>,
    exchanges: Arc<Mutex<Vec<Form>>>,
}

async fn github(AxumState(stub): AxumState<GitHubStub>, request: Request) -> Response {
    if matches!(request.uri().path(), "/token" | "/user") {
        assert_eq!(header(request.headers(), "user-agent"), "scimtest-server");
    }
    match request.uri().path() {
        "/authorize" => {
            let values = query(&request);
            assert_eq!(field(&values, "client_id"), "greendale-client");
            assert_eq!(field(&values, "code_challenge_method"), "S256");
            assert_eq!(field(&values, "code_challenge").len(), 43);
            let mut callback = Url::parse(field(&values, "redirect_uri")).unwrap();
            callback
                .query_pairs_mut()
                .append_pair("state", field(&values, "state"))
                .append_pair("code", "paintball");
            let mut templates = minijinja::Environment::new();
            templates.add_template("provider.html","<!doctype html><title>Local GitHub test provider</title><h1>Local GitHub test provider</h1><p>Use the disposable test account.</p><a href=\"{{ callback }}\">Approve local test sign-in</a>").unwrap();
            crate::server::text_response(
                StatusCode::OK,
                "text/html; charset=utf-8",
                templates
                    .get_template("provider.html")
                    .unwrap()
                    .render(json!({"callback":callback.as_str()}))
                    .unwrap(),
            )
        }
        "/token" => {
            assert_eq!(request.method(), "POST");
            assert_eq!(header(request.headers(), "accept"), "application/json");
            let values = form(request, 4096).await.unwrap();
            assert_eq!(field(&values, "client_id"), "greendale-client");
            assert_eq!(field(&values, "client_secret"), "greendale-secret");
            assert!(valid_hex(field(&values, "code_verifier"), 64));
            let denied = field(&values, "code") == "token-error";
            let status = if field(&values, "code") == "token-redirect" {
                StatusCode::FOUND
            } else {
                StatusCode::OK
            };
            lock(&stub.exchanges).push(values);
            (
                status,
                axum::Json(if denied {
                    json!({"error":"bad_verification_code"})
                } else {
                    json!({"access_token":"github-secret-stays-on-server"})
                }),
            )
                .into_response()
        }
        "/user" => {
            assert_eq!(
                header(request.headers(), "authorization"),
                "Bearer github-secret-stays-on-server"
            );
            assert_eq!(
                header(request.headers(), "accept"),
                "application/vnd.github+json"
            );
            let user = lock(&stub.user);
            let status = if user.login == "upstream-created" {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            (status, axum::Json(json!({"id":user.id,"login":user.login}))).into_response()
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

struct Running {
    directory: tempfile::TempDir,
    server: Server,
    profile: String,
    base: String,
    client: Client,
    stub: GitHubStub,
    shutdown: CancellationToken,
    task: Option<JoinHandle<anyhow::Result<()>>>,
    github_task: JoinHandle<()>,
}

impl Running {
    async fn new(secure: bool, limit: usize) -> Self {
        Self::configured(secure, limit, false).await
    }

    async fn configured(secure: bool, limit: usize, loopback_public: bool) -> Self {
        Self::configured_provider(secure, limit, loopback_public, false).await
    }

    async fn configured_provider(
        secure: bool,
        limit: usize,
        loopback_public: bool,
        local_authorize: bool,
    ) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let github_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let github_base = format!("http://{}", github_listener.local_addr().unwrap());
        let stub = GitHubStub {
            user: Arc::new(Mutex::new(GitHubUser {
                id: 101,
                login: "troy-barnes".into(),
            })),
            exchanges: Arc::new(Mutex::new(Vec::new())),
        };
        let app = Router::new().fallback(github).with_state(stub.clone());
        let github_task = tokio::spawn(async move {
            axum::serve(github_listener, app).await.unwrap();
        });
        let mut server = Server::new(Config {
            domain: if loopback_public {
                address.to_string()
            } else {
                "public.greendale.test".into()
            },
            dashboard_domain: if loopback_public {
                format!("admin.localhost:{}", address.port())
            } else {
                "admin.greendale.test".into()
            },
            public_scheme: if secure { "https" } else { "http" }.into(),
            data_path: directory.path().join("server.json"),
            github_client_id: "greendale-client".into(),
            github_client_secret: "greendale-secret".into(),
            max_installations_per_user: limit,
            shutdown_timeout: StdDuration::from_secs(3),
            ..Config::default()
        })
        .unwrap();
        let inner = Arc::get_mut(&mut server.0).unwrap();
        inner.github.token_url = format!("{github_base}/token");
        inner.github.user_url = format!("{github_base}/user");
        if local_authorize {
            inner.github.authorize_url = format!("{github_base}/authorize");
        }
        inner.github.client = Client::builder()
            .no_proxy()
            .timeout(StdDuration::from_secs(3))
            .build()
            .unwrap();
        let profile = server
            .store()
            .create_profile(ApplicationSettings {
                name: "Greendale Community College".into(),
                public_key: support::public_key(42),
                routes: parse_routes("GET /oidc/{slug}/jwks").unwrap(),
                requests_per_minute: 60,
                request_burst: 10,
                concurrent_requests: 4,
            })
            .unwrap()
            .id;
        let base = format!("http://{address}");
        let shutdown = CancellationToken::new();
        let task = Some(tokio::spawn(
            server.clone().serve(listener, shutdown.clone()),
        ));
        Self {
            directory,
            server,
            profile,
            base,
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            stub,
            shutdown,
            task,
            github_task,
        }
    }

    fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}{path}", self.base))
            .header("host", &self.server.0.config.dashboard_domain)
    }

    async fn oauth(&self, start: reqwest::Response, code: &str) -> reqwest::Response {
        assert_eq!(start.status(), StatusCode::FOUND);
        let state_cookie = response_cookie(&start, &self.server.0.cookie_name(STATE_COOKIE));
        let url = Url::parse(start.headers()["location"].to_str().unwrap()).unwrap();
        assert_eq!(url.origin().ascii_serialization(), "https://github.com");
        let values: Form = url.query_pairs().into_owned().collect();
        assert_eq!(
            field(&values, "state"),
            state_cookie.split_once('=').unwrap().1
        );
        assert_eq!(field(&values, "code_challenge_method"), "S256");
        assert_eq!(field(&values, "redirect_uri"), self.server.0.callback_url());
        let response = self
            .request(
                Method::GET,
                &format!(
                    "/auth/github/callback?state={}&code={code}",
                    field(&values, "state")
                ),
            )
            .header("cookie", state_cookie)
            .send()
            .await
            .unwrap();
        let exchanges = lock(&self.stub.exchanges);
        if let Some(exchange) = exchanges.last() {
            assert_eq!(
                field(&values, "code_challenge"),
                URL_SAFE_NO_PAD.encode(Sha256::digest(field(exchange, "code_verifier").as_bytes()))
            );
            assert_eq!(
                field(exchange, "redirect_uri"),
                self.server.0.callback_url()
            );
        }
        response
    }

    async fn approve(&self, required: &Message) -> reqwest::Response {
        let handoff = Url::parse(&required.enrollment_browser_handoff_url).unwrap();
        let start = self
            .request(
                Method::GET,
                &format!("{}?{}", handoff.path(), handoff.query().unwrap()),
            )
            .send()
            .await
            .unwrap();
        self.oauth(start, "paintball").await
    }

    async fn poll(&self, device: &str) -> reqwest::Response {
        self.client
            .post(format!("{}/api/enroll/status", self.base))
            .header("host", "public.greendale.test")
            .bearer_auth(device)
            .send()
            .await
            .unwrap()
    }

    async fn dial(
        &self,
        seed: u8,
        legacy: &str,
        grant: &str,
        signer: u8,
    ) -> (Socket, tungstenite::Message) {
        let (mut socket, _) = connect_async(self.base.replacen("http", "ws", 1) + "/api/connect")
            .await
            .unwrap();
        let key = SigningKey::from_bytes(&[seed; 32]);
        let public = STANDARD.encode(key.verifying_key().as_bytes());
        socket
            .send(tungstenite::Message::text(
                serde_json::to_string(&Message {
                    kind: "register_tunnel".into(),
                    application_profile_id: self.profile.clone(),
                    instance_id: legacy.into(),
                    instance_public_key: public.clone(),
                    local_port: 4321,
                    ..Default::default()
                })
                .unwrap(),
            ))
            .await
            .unwrap();
        let challenge = read_message(&mut socket).await;
        assert_eq!(challenge.kind, "application_challenge");
        assert!(challenge.enrollment_supported);
        let signature = SigningKey::from_bytes(&[signer; 32]).sign(&instance_challenge_payload(
            &self.profile,
            &public,
            legacy,
            &challenge.challenge,
        ));
        socket
            .send(tungstenite::Message::text(
                serde_json::to_string(&Message {
                    kind: "application_signature".into(),
                    signature: signature.to_bytes().into(),
                    enrollment_grant: grant.into(),
                    ..Default::default()
                })
                .unwrap(),
            ))
            .await
            .unwrap();
        let reply = tokio::time::timeout(StdDuration::from_secs(3), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        (socket, reply)
    }

    fn pending(&self, seed: u8, ip: &str) -> Message {
        self.server
            .0
            .begin_enrollment(self.binding(seed, ""), ip)
            .unwrap()
    }

    fn binding(&self, seed: u8, legacy: &str) -> Binding {
        let key = STANDARD.encode(
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .as_bytes(),
        );
        let (_, instance) = parse_instance_key(&key).unwrap();
        Binding {
            profile: self.profile.clone(),
            instance,
            key,
            legacy: legacy.into(),
        }
    }

    async fn disconnect(&self, mut socket: Socket) {
        socket.close(None).await.unwrap();
        self.wait_disconnected().await;
    }

    async fn server_closed(&self, mut socket: Socket) {
        let message = tokio::time::timeout(StdDuration::from_secs(3), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(
            matches!(message, tungstenite::Message::Close(_)),
            "{message:?}"
        );
        drop(socket);
        self.wait_disconnected().await;
    }

    async fn wait_disconnected(&self) {
        tokio::time::timeout(StdDuration::from_secs(3), async {
            loop {
                if lock(&self.server.0.tunnels).is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    async fn stop(&mut self) {
        self.shutdown.cancel();
        if let Some(task) = self.task.take() {
            task.await.unwrap().unwrap();
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
        self.github_task.abort();
    }
}

async fn read_message(socket: &mut Socket) -> Message {
    let message = tokio::time::timeout(StdDuration::from_secs(3), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    decode(message)
}

fn decode(message: tungstenite::Message) -> Message {
    serde_json::from_slice(&message.into_data()).unwrap()
}

fn closed(message: tungstenite::Message, reason: &str) {
    match message {
        tungstenite::Message::Close(Some(frame)) => {
            assert_eq!(u16::from(frame.code), 1008);
            assert!(frame.reason.contains(reason), "{frame:?}");
        }
        other => panic!("wanted a policy close, got {other:?}"),
    }
}

fn response_cookie(response: &reqwest::Response, name: &str) -> String {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .rfind(|value| value.starts_with(&format!("{name}=")))
        .unwrap_or_else(|| panic!("missing cookie {name}: {:?}", response.headers()))
        .split(';')
        .next()
        .unwrap()
        .into()
}

fn csrf(html: &str) -> &str {
    html.split("name=\"csrf_token\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
}

#[tokio::test]
async fn oauth_uses_pkce_single_use_state_and_host_only_cookies_with_persisted_sessions() {
    let mut app = Running::new(true, 5).await;
    lock(&app.stub.user).login = " RSELBACH ".into();
    let start = app
        .request(Method::GET, "/login/github")
        .send()
        .await
        .unwrap();
    let state_cookie = response_cookie(&start, "__Host-scimtest_oauth_state");
    let attributes = start.headers()["set-cookie"].to_str().unwrap();
    for attribute in [
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Path=/",
        "Max-Age=600",
    ] {
        assert!(attributes.contains(attribute));
    }
    assert!(!attributes.contains("Domain="));
    let state = state_cookie.split_once('=').unwrap().1;
    let wrong = app
        .request(
            Method::GET,
            &format!("/auth/github/callback?state={state}&code=paintball"),
        )
        .header("cookie", "__Host-scimtest_oauth_state=wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);
    assert!(lock(&app.stub.exchanges).is_empty());
    let response = app.oauth(start, "paintball").await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers()["location"], "/dashboard");
    let session = response_cookie(&response, "__Host-scimtest_session");
    let replay = app
        .request(
            Method::GET,
            &format!("/auth/github/callback?state={state}&code=paintball"),
        )
        .header("cookie", &state_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert_eq!(lock(&app.stub.exchanges).len(), 1);
    let page = app
        .request(Method::GET, "/dashboard")
        .header("cookie", &session)
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(page.headers()["cache-control"], "no-store");
    assert!(
        page.text()
            .await
            .unwrap()
            .contains("Greendale Community College")
    );
    let store = Store::open(app.directory.path().join("server.json")).unwrap();
    assert!(
        store
            .session(session.split_once('=').unwrap().1)
            .unwrap()
            .is_some()
    );
    let disk = std::fs::read_to_string(app.directory.path().join("server.json")).unwrap();
    for secret in ["github-secret-stays-on-server", "greendale-secret", state] {
        assert!(!disk.contains(secret));
    }
    app.stop().await;
}

#[tokio::test]
async fn oauth_denies_non_admin_dashboard_and_reports_upstream_failures_without_creating_sessions()
{
    let mut app = Running::new(false, 5).await;
    for (code, user, want, message) in [
        (
            "paintball",
            GitHubUser {
                id: 101,
                login: "troy-barnes".into(),
            },
            StatusCode::FORBIDDEN,
            "not allowed",
        ),
        (
            "token-error",
            GitHubUser {
                id: 101,
                login: "rselbach".into(),
            },
            StatusCode::BAD_GATEWAY,
            "GitHub token exchange failed",
        ),
        (
            "paintball",
            GitHubUser {
                id: 0,
                login: "rselbach".into(),
            },
            StatusCode::BAD_GATEWAY,
            "GitHub user lookup failed",
        ),
        (
            "token-redirect",
            GitHubUser {
                id: 101,
                login: "rselbach".into(),
            },
            StatusCode::BAD_GATEWAY,
            "GitHub token exchange failed",
        ),
        (
            "paintball",
            GitHubUser {
                id: 101,
                login: "upstream-created".into(),
            },
            StatusCode::BAD_GATEWAY,
            "GitHub user lookup failed",
        ),
    ] {
        *lock(&app.stub.user) = user;
        let start = app
            .request(Method::GET, "/login/github")
            .send()
            .await
            .unwrap();
        let response = app.oauth(start, code).await;
        assert_eq!(response.status(), want);
        assert!(
            !response
                .headers()
                .get_all("set-cookie")
                .iter()
                .any(|value| value.to_str().unwrap().starts_with("scimtest_session="))
        );
        assert!(response.text().await.unwrap().contains(message));
    }
    let unknown = app
        .request(
            Method::GET,
            "/auth/github/callback?state=unknown&code=paintball",
        )
        .header("cookie", "scimtest_oauth_state=unknown")
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
    assert_eq!(lock(&app.stub.exchanges).len(), 5);
    app.stop().await;
}

#[path = "enrollment_tests.rs"]
mod enrollment_tests;

#[path = "dashboard_tests.rs"]
mod dashboard_tests;

#[path = "client_tests.rs"]
mod client_tests;

#[path = "shared_tests.rs"]
mod shared_tests;

#[tokio::test]
async fn dashboard_confirmation_origins_match_the_actual_go_service() {
    let app = Running::new(true, 5).await;
    let mut cases = Vec::new();
    let mut requests = Vec::new();
    for host in [
        "admin.greendale.test",
        "public.greendale.test",
        "localhost:7000",
        "127.0.0.1:7000",
        "[::1]:7000",
        "evil.greendale.test",
    ] {
        for origin in [
            "https://admin.greendale.test",
            "https://ADMIN.GREENDALE.TEST:443",
            "http://admin.greendale.test",
            "https://admin.greendale.test/",
            "https://admin.greendale.test//",
            "https://admin.greendale.test/..",
            "https://admin.greendale.test/%2e%2e",
            "https://admin.greendale.test/%2f",
            "https://admin.greendale.test?",
            "https://admin.greendale.test#",
            "https://admin.greendale.test#x",
            "https://user@admin.greendale.test",
            "https://admin.greendale.test.evil/",
            "http://localhost:7000",
            "http://127.0.0.1:7000",
            "http://127.0.0.1:7001",
            "http://[::1]:7000",
            "null",
            "",
        ] {
            for site in ["", "same-origin", "cross-site"] {
                cases.push(json!({"kind":"dashboard_mutation","host":host,"origin":origin,"site":site,"value":"https"}));
                requests.push(
                    Request::builder()
                        .method("POST")
                        .uri("/enroll")
                        .header("host", host)
                        .header("origin", origin)
                        .header("sec-fetch-site", site)
                        .body(Body::empty())
                        .unwrap(),
                );
            }
        }
    }
    let reference = support::GoFixture::new().run(json!({"kind":"policy","policies":cases}));
    for ((case, request), want) in cases
        .iter()
        .zip(requests)
        .zip(reference.as_array().unwrap())
    {
        assert_eq!(
            json!(app.server.0.allowed_mutation(&request)),
            *want,
            "{case}"
        );
    }
    println!("Compared {} confirmation origins with Go", cases.len());
}
