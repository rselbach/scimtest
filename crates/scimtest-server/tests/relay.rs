mod support;

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use reqwest::{Client, StatusCode};
use scimtest_protocol::{Message, application_challenge_payload, instance_challenge_payload};
use scimtest_server::{
    Config, Server,
    application::{ApplicationSettings, parse_instance_key, parse_routes},
    store::{EnrollmentActor, Store},
};
use serde_json::json;
use std::time::Duration;
use support::public_key;
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite};
use tokio_util::sync::CancellationToken;

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

struct Running {
    _directory: tempfile::TempDir,
    server: Server,
    base: String,
    profile: String,
    shutdown: CancellationToken,
    task: JoinHandle<anyhow::Result<()>>,
    client: Client,
}

impl Running {
    async fn new(mut configure: impl FnMut(&mut Config, &mut ApplicationSettings)) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let mut config = Config {
            data_path: directory.path().join("server.json"),
            domain: "public.greendale.test".into(),
            dashboard_domain: "admin.greendale.test".into(),
            shutdown_timeout: Duration::from_secs(3),
            max_body_bytes: 512 << 10,
            ..Config::default()
        };
        let mut settings = ApplicationSettings {
            name: "Greendale Community College".into(),
            public_key: public_key(42),
            routes: parse_routes("GET,POST /echo/{name}\nGET /body\nGET /hang").unwrap(),
            requests_per_minute: 600,
            request_burst: 100,
            concurrent_requests: 2,
        };
        configure(&mut config, &mut settings);
        let store = Store::open(&config.data_path).unwrap();
        let profile = store.create_profile(settings).unwrap().id;
        let key = STANDARD.encode(SigningKey::from_bytes(&[24; 32]).verifying_key().as_bytes());
        let (_, id) = parse_instance_key(&key).unwrap();
        store
            .enroll_instance(
                &profile,
                &id,
                &key,
                EnrollmentActor {
                    github_user_id: 101,
                    github_login: "troy-barnes".into(),
                },
            )
            .unwrap();
        store
            .remember_tunnel(&profile, &id, "greendale-study-group", true)
            .unwrap();
        store
            .remember_tunnel(&profile, "legacy-greendale", "human-timeline-club", false)
            .unwrap();
        let server = Server::new(config).unwrap();
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(server.clone().serve(listener, shutdown.clone()));
        Self {
            _directory: directory,
            server,
            base,
            profile,
            shutdown,
            task,
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        }
    }

    async fn socket(&self) -> Socket {
        connect_async(self.base.replacen("http", "ws", 1) + "/api/connect")
            .await
            .unwrap()
            .0
    }

    async fn register(&self, legacy: bool) -> (Socket, Message) {
        let mut socket = self.socket().await;
        self.authenticate(
            &mut socket,
            legacy,
            &self.profile,
            if legacy { 42 } else { 24 },
        )
        .await;
        let message = read(&mut socket).await;
        assert_eq!(message.kind, "tunnel_registered");
        (socket, message)
    }

    async fn authenticate(&self, socket: &mut Socket, legacy: bool, profile: &str, signer: u8) {
        let key = STANDARD.encode(SigningKey::from_bytes(&[24; 32]).verifying_key().as_bytes());
        send(
            socket,
            Message {
                kind: "register_tunnel".into(),
                application_profile_id: profile.into(),
                instance_id: if legacy {
                    "legacy-greendale".into()
                } else {
                    String::new()
                },
                instance_public_key: if legacy { String::new() } else { key.clone() },
                local_port: 4321,
                ..Default::default()
            },
        )
        .await;
        let challenge = read(socket).await;
        assert_eq!(challenge.kind, "application_challenge");
        assert_eq!(challenge.enrollment_supported, !legacy);
        let payload = if legacy {
            application_challenge_payload(profile, "legacy-greendale", &challenge.challenge)
        } else {
            instance_challenge_payload(profile, &key, "", &challenge.challenge)
        };
        send(
            socket,
            Message {
                kind: "application_signature".into(),
                signature: SigningKey::from_bytes(&[signer; 32])
                    .sign(&payload)
                    .to_bytes()
                    .to_vec(),
                ..Default::default()
            },
        )
        .await;
    }

    async fn active(&self, want: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let metrics: serde_json::Value = self
                    .client
                    .get(format!("{}/api/metrics", self.base))
                    .header("host", "admin.greendale.test")
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                if metrics["tunnels_active"] == want {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    async fn stop(mut self) {
        self.shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(4), &mut self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.task.abort();
    }
}

async fn send(socket: &mut Socket, message: Message) {
    socket
        .send(tungstenite::Message::Text(
            serde_json::to_string(&message).unwrap().into(),
        ))
        .await
        .unwrap();
}

async fn read(socket: &mut Socket) -> Message {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match socket.next().await.unwrap().unwrap() {
                tungstenite::Message::Text(text) => {
                    return Message::decode(text.as_bytes()).unwrap();
                }
                tungstenite::Message::Binary(bytes) => return Message::decode(&bytes).unwrap(),
                tungstenite::Message::Ping(_) | tungstenite::Message::Pong(_) => continue,
                other => panic!("unexpected socket message: {other:?}"),
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_tunnel_preserves_binary_bodies_headers_and_public_boundaries() {
    let app = Running::new(|_, _| {}).await;
    let (mut socket, registered) = app.register(false).await;
    assert_eq!(registered.github_user_id, 101);
    assert_eq!(registered.github_login, "troy-barnes");
    assert_eq!(registered.client_ip, "127.0.0.1");
    assert_eq!(
        registered.public_url,
        "http://public.greendale.test/greendale-study-group"
    );
    let body: Vec<u8> = (0..131072).map(|index| (index % 256) as u8).collect();
    let request = app
        .client
        .post(format!(
            "{}/greendale-study-group/echo/troy?team=Troy%20and%20Abed",
            app.base
        ))
        .header("host", "public.greendale.test")
        .header("connection", "x-greendale-private")
        .header("x-greendale-private", "remove-me")
        .header("proxy-authorization", "Basic test-only")
        .header("x-forwarded-for", "198.51.100.42")
        .header("x-forwarded-host", "evil.greendale.test")
        .header("x-forwarded-proto", "https")
        .body(body.clone());
    let response = tokio::spawn(async move { request.send().await.unwrap() });
    let forwarded = read(&mut socket).await;
    assert_eq!(forwarded.kind, "request");
    assert_eq!(forwarded.body, body);
    assert_eq!(
        forwarded.path,
        "/greendale-study-group/echo/troy?team=Troy%20and%20Abed"
    );
    assert_eq!(forwarded.header["X-Forwarded-For"], ["127.0.0.1"]);
    assert_eq!(
        forwarded.header["X-Forwarded-Host"],
        ["public.greendale.test"]
    );
    assert_eq!(forwarded.header["X-Forwarded-Proto"], ["http"]);
    assert!(!forwarded.header.contains_key("X-Greendale-Private"));
    assert!(!forwarded.header.contains_key("Proxy-Authorization"));
    let returned: Vec<_> = body.into_iter().rev().collect();
    send(&mut socket,Message{kind:"response".into(),stream_id:forwarded.stream_id,status_code:201,
        header:serde_json::from_value(json!({"Content-Type":["application/octet-stream"],"Connection":["X-Greendale-Private"],"X-Greendale-Private":["remove-me"],"Set-Cookie":["troy=Greendale","abed=Community"],"X-Frame-Options":["SAMEORIGIN"]})).unwrap(),body:returned.clone(),..Default::default()}).await;
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers().get_all("set-cookie").iter().count(), 2);
    assert_eq!(response.headers()["x-frame-options"], "SAMEORIGIN");
    assert!(!response.headers().contains_key("x-greendale-private"));
    assert_eq!(response.bytes().await.unwrap().as_ref(), returned);
    let denied = app
        .client
        .get(format!("{}/greendale-study-group/api/v1/users", app.base))
        .header("host", "public.greendale.test")
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::NOT_FOUND);
    let unknown = app
        .client
        .get(format!("{}/healthz", app.base))
        .header("host", "unknown.greendale.test")
        .send()
        .await
        .unwrap();
    assert_eq!(
        unknown.status(),
        StatusCode::OK,
        "health is intentionally host independent"
    );
    assert!(!unknown.headers().contains_key("x-frame-options"));
    app.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn busy_body_limits_status_clamping_and_disconnects_match_the_go_contract() {
    let app = Running::new(|_, settings| settings.concurrent_requests = 1).await;
    let (mut socket, _) = app.register(false).await;
    let request = app
        .client
        .get(format!("{}/greendale-study-group/hang", app.base))
        .header("host", "public.greendale.test");
    let waiting = tokio::spawn(async move { request.send().await.unwrap() });
    let first = read(&mut socket).await;
    let busy = app
        .client
        .get(format!("{}/greendale-study-group/body", app.base))
        .header("host", "public.greendale.test")
        .send()
        .await
        .unwrap();
    assert_eq!(busy.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(busy.text().await.unwrap().contains("tunnel busy"));
    send(
        &mut socket,
        Message {
            kind: "response".into(),
            stream_id: first.stream_id,
            body: b"Troy and Abed".to_vec(),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        waiting.await.unwrap().text().await.unwrap(),
        "Troy and Abed"
    );
    let oversized = app
        .client
        .post(format!("{}/greendale-study-group/echo/troy", app.base))
        .header("host", "public.greendale.test")
        .body(vec![0; 512 * 1024 + 1])
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    for (status, want) in [(-1, 502), (99999, 502), (7, 502), (0, 200), (418, 418)] {
        let request = app
            .client
            .get(format!("{}/greendale-study-group/body", app.base))
            .header("host", "public.greendale.test");
        let response = tokio::spawn(async move { request.send().await.unwrap() });
        let forwarded = read(&mut socket).await;
        send(
            &mut socket,
            Message {
                kind: "response".into(),
                stream_id: forwarded.stream_id,
                status_code: status,
                body: b"Greendale".to_vec(),
                ..Default::default()
            },
        )
        .await;
        let response = response.await.unwrap();
        assert_eq!(response.status().as_u16(), want);
        assert_eq!(response.text().await.unwrap(), "Greendale");
    }
    let request = app
        .client
        .get(format!("{}/greendale-study-group/hang", app.base))
        .header("host", "public.greendale.test");
    let waiting = tokio::spawn(async move { request.send().await.unwrap() });
    read(&mut socket).await;
    socket.close(None).await.unwrap();
    let response = waiting.await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(
        response
            .text()
            .await
            .unwrap()
            .contains("tunnel disconnected")
    );
    app.active(0).await;
    app.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicate_and_profile_limits_preserve_the_reserved_url_on_reconnect() {
    let app = Running::new(|config, _| config.max_tunnels_per_application = 1).await;
    let (mut socket, first) = app.register(false).await;
    for legacy in [false, true] {
        let mut duplicate = app.socket().await;
        app.authenticate(
            &mut duplicate,
            legacy,
            &app.profile,
            if legacy { 42 } else { 24 },
        )
        .await;
        let tungstenite::Message::Close(Some(close)) = duplicate.next().await.unwrap().unwrap()
        else {
            panic!("expected policy close")
        };
        assert_eq!(u16::from(close.code), 1008);
        assert!(close.reason.contains(if legacy {
            "maximum number of tunnels"
        } else {
            "already has an active tunnel"
        }));
    }
    socket.close(None).await.unwrap();
    app.active(0).await;
    let (mut socket, second) = app.register(false).await;
    assert_eq!(first.public_url, second.public_url);
    socket.close(None).await.unwrap();
    app.active(0).await;
    let (_, legacy) = app.register(true).await;
    assert_eq!(
        legacy.public_url,
        "http://public.greendale.test/human-timeline-club"
    );
    assert!(legacy.github_login.is_empty());
    app.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unauthenticated_connections_are_bounded_and_release_their_slots() {
    let app = Running::new(|_, _| {}).await;
    let mut sockets = Vec::new();
    for _ in 0..8 {
        sockets.push(app.socket().await);
    }
    let error = connect_async(app.base.replacen("http", "ws", 1) + "/api/connect")
        .await
        .unwrap_err();
    let tungstenite::Error::Http(response) = error else {
        panic!("expected HTTP capacity rejection")
    };
    assert_eq!(response.status(), 503);
    let mut socket = sockets.pop().unwrap();
    socket.close(None).await.unwrap();
    drop(socket);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok((socket, _)) =
                connect_async(app.base.replacen("http", "ws", 1) + "/api/connect").await
            {
                drop(socket);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(sockets);
    app.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_registration_closes_with_the_go_message_size_code() {
    let app = Running::new(|_, _| {}).await;
    let mut socket = app.socket().await;
    socket
        .send(tungstenite::Message::Text(
            "Greendale ".repeat(10_000).into(),
        ))
        .await
        .unwrap();
    let tungstenite::Message::Close(Some(close)) = socket.next().await.unwrap().unwrap() else {
        panic!("expected size rejection")
    };
    assert_eq!(u16::from(close.code), 1009);
    assert_eq!(close.reason, "read limit exceeded");
    app.active(0).await;
    app.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signature_revocation_host_origin_and_method_checks_reject_before_forwarding() {
    use tungstenite::client::IntoClientRequest;
    let app = Running::new(|_, _| {}).await;
    let mut wrong = app.socket().await;
    app.authenticate(&mut wrong, false, &app.profile, 25).await;
    let tungstenite::Message::Close(Some(close)) = wrong.next().await.unwrap().unwrap() else {
        panic!("expected signature rejection")
    };
    assert_eq!(u16::from(close.code), 1008);
    assert_eq!(close.reason, "invalid instance signature");
    let key = STANDARD.encode(SigningKey::from_bytes(&[24; 32]).verifying_key().as_bytes());
    let (_, id) = parse_instance_key(&key).unwrap();
    assert!(
        app.server
            .store()
            .set_instance_revoked(&app.profile, &id, true)
            .unwrap()
    );
    let mut revoked = app.socket().await;
    app.authenticate(&mut revoked, false, &app.profile, 24)
        .await;
    let tungstenite::Message::Close(Some(close)) = revoked.next().await.unwrap().unwrap() else {
        panic!("expected revocation rejection")
    };
    assert_eq!(u16::from(close.code), 1008);
    assert_eq!(close.reason, "installation revoked");
    let mut request = (app.base.replacen("http", "ws", 1) + "/api/connect")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("host", "unknown.greendale.test".parse().unwrap());
    let tungstenite::Error::Http(response) = connect_async(request).await.unwrap_err() else {
        panic!("expected host rejection")
    };
    assert_eq!(response.status(), 404);
    let mut request = (app.base.replacen("http", "ws", 1) + "/api/connect")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("origin", "https://evil.greendale.test".parse().unwrap());
    let tungstenite::Error::Http(response) = connect_async(request).await.unwrap_err() else {
        panic!("expected origin rejection")
    };
    assert_eq!(response.status(), 403);
    let response = app
        .client
        .post(format!("{}/api/connect", app.base))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers()["allow"], "GET");
    let response = app
        .client
        .get(format!("{}/api/metrics", app.base))
        .header("host", "public.greendale.test")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    app.active(0).await;
    app.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forwarded_identity_uses_the_closest_untrusted_hop_only_behind_a_trusted_proxy() {
    for trusted in [true, false] {
        let app = Running::new(|config, _| {
            config.behind_proxy = true;
            if !trusted {
                config.trusted_proxy_cidrs = vec!["10.0.0.0/8".into()];
            }
        })
        .await;
        let (mut socket, registered) = app.register(false).await;
        assert!(registered.public_url.starts_with("https://"));
        let request = app
            .client
            .get(format!("{}/greendale-study-group/body", app.base))
            .header("host", "public.greendale.test")
            .header("x-forwarded-for", "198.51.100.42, 10.0.0.1, 127.0.0.2")
            .header("x-forwarded-proto", "https");
        let response = tokio::spawn(async move { request.send().await.unwrap() });
        let forwarded = read(&mut socket).await;
        assert_eq!(
            forwarded.header["X-Forwarded-For"],
            [if trusted { "10.0.0.1" } else { "127.0.0.1" }]
        );
        assert_eq!(forwarded.scheme, if trusted { "https" } else { "http" });
        send(
            &mut socket,
            Message {
                kind: "response".into(),
                stream_id: forwarded.stream_id,
                ..Default::default()
            },
        )
        .await;
        assert_eq!(response.await.unwrap().text().await.unwrap(), "");
        let response = app
            .client
            .get(format!("{}/greendale-study-group/body", app.base))
            .header("host", "public.greendale.test..")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        app.stop().await;
    }
}
