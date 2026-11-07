#[path = "tunnel/server.rs"]
mod server;
use axum::{
    Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use scimtest_core::{
    Store,
    tunnel::{Config, Service, Snapshot},
};
use serde_json::{Value, json};
use server::{Command, Server};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Local {
    port: u16,
    reached: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Local {
    async fn new() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let reached = Arc::new(AtomicUsize::new(0));
        let app = Router::new().fallback(local).with_state(reached.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            port,
            reached,
            task,
        }
    }
}
impl Drop for Local {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn local(State(reached): State<Arc<AtomicUsize>>, request: Request) -> Response {
    reached.fetch_add(1, Ordering::SeqCst);
    if request.uri().path() == "/slow" {
        std::future::pending::<()>().await;
    }
    if request.uri().path() == "/large" {
        return vec![b'x'; (32 << 20) + 1].into_response();
    }
    let uri = request.uri().to_string();
    let headers = request.headers().clone();
    let body = to_bytes(request.into_body(), 32 << 20).await.unwrap();
    if uri == "/body-size" {
        return body.len().to_string().into_response();
    }
    let value = json!({"uri":uri,"host":headers["host"].to_str().unwrap(),"body":STANDARD.encode(body),"kept":headers.get("x-greendale").and_then(|value| value.to_str().ok()),"dropped":headers.get("x-drop").and_then(|value| value.to_str().ok())});
    let mut headers = HeaderMap::new();
    headers.append("set-cookie", HeaderValue::from_static("troy=1"));
    headers.append("set-cookie", HeaderValue::from_static("abed=2"));
    headers.insert("connection", HeaderValue::from_static("X-Response-Hop"));
    headers.insert("x-response-hop", HeaderValue::from_static("remove"));
    headers.insert("x--greendale", HeaderValue::from_static("preserve"));
    headers.insert(
        "location",
        HeaderValue::from_static("https://citycollege.example/callback"),
    );
    (StatusCode::FOUND, headers, value.to_string()).into_response()
}
fn service(store: Store, server: &Server, local: &Local) -> Service {
    Service::new(
        store,
        Some(Config {
            server_base_url: server.shared.base.clone(),
            application_profile_id: "0123456789abcdef0123456789abcdef".into(),
            require_account: true,
        }),
        local.port,
    )
    .unwrap()
}
async fn wait(service: &Service, predicate: impl Fn(&Snapshot) -> bool) -> Snapshot {
    tokio::time::timeout(std::time::Duration::from_secs(8), async {
        loop {
            let snapshot = service.snapshot().unwrap();
            if predicate(&snapshot) {
                break snapshot;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn enrollment_authenticates_the_installation_without_exposing_the_device_secret_and_logout_changes_accounts()
 {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    let server = Server::new(true).await;
    let local = Local::new().await;
    server.shared.poll_error.store(429, Ordering::SeqCst);
    let service = service(store.clone(), &server, &local);
    service.start().unwrap();
    let authorizing = wait(&service, |snapshot| snapshot.state() == "authorizing").await;
    assert!(!service.unlocked().unwrap());
    assert!(
        authorizing
            .enrollment_url
            .contains("/enroll/browser?handoff=one-use")
    );
    assert!(authorizing.enrollment_url.contains("presentation=desktop"));
    assert_eq!(
        service.authorization_url().unwrap(),
        format!("{}/enroll/browser?handoff=one-use", server.shared.base)
    );
    assert_eq!(authorizing.enrollment_code, "GREEN-DALE");
    assert!(
        !service
            .account()
            .unwrap()
            .to_string()
            .contains("greendale-device-secret")
    );
    server.shared.approved.store(true, Ordering::SeqCst);
    let connected = wait(&service, |snapshot| snapshot.connected).await;
    assert_eq!(
        connected.public_url.as_deref(),
        Some("https://scimtest.example/greendale")
    );
    assert!(service.unlocked().unwrap());
    assert_eq!(service.account().unwrap()["login"], "troy-barnes");
    assert!(server.shared.polls.load(Ordering::SeqCst) >= 2);
    let first = store.installation_identity().unwrap();
    server.shared.approved.store(false, Ordering::SeqCst);
    *server.shared.login.lock().unwrap() = "abed-nadir".into();
    service.logout().await.unwrap();
    wait(&service, |snapshot| snapshot.state() == "authorizing").await;
    assert!(!service.unlocked().unwrap());
    assert_ne!(
        store.installation_identity().unwrap().fingerprint(),
        first.fingerprint()
    );
    server.shared.approved.store(true, Ordering::SeqCst);
    wait(&service, |snapshot| snapshot.connected).await;
    assert_eq!(service.account().unwrap()["login"], "abed-nadir");
    let credentials = server.shared.credentials.lock().unwrap().clone();
    assert_eq!(credentials.len(), 4);
    assert!(credentials[0]["grant"].is_null());
    assert_eq!(credentials[1]["grant"], "greendale-device-secret");
    assert_ne!(credentials[0]["public_key"], credentials[2]["public_key"]);
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn reconnect_preserves_identity_and_updates_registration_then_policy_close_relocks_the_account()
 {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    let server = Server::new(false).await;
    let local = Local::new().await;
    let service = service(store, &server, &local);
    service.start().unwrap();
    wait(&service, |snapshot| snapshot.connected).await;
    *server.shared.public_url.lock().unwrap() = "https://scimtest.example/study-group".into();
    server
        .commands
        .send(Command::Close(1001, "Greendale restart".into()))
        .unwrap();
    wait(&service, |snapshot| {
        snapshot.public_url.as_deref() == Some("https://scimtest.example/study-group")
    })
    .await;
    let credentials = server.shared.credentials.lock().unwrap().clone();
    assert_eq!(credentials.len(), 2);
    assert_eq!(credentials[0]["public_key"], credentials[1]["public_key"]);
    assert_eq!(credentials[0]["instance_id"], credentials[1]["instance_id"]);
    assert_eq!(
        service.public_endpoint().unwrap().unwrap().prefix,
        "/study-group"
    );
    server
        .commands
        .send(Command::Close(1008, "installation revoked".into()))
        .unwrap();
    wait(&service, |snapshot| snapshot.retry_available).await;
    assert!(!service.unlocked().unwrap());
    assert!(service.public_endpoint().unwrap().is_none());
    assert_eq!(
        service.account().unwrap()["error"],
        "the tunnel operator revoked this installation; sign-in is required before the desktop app can unlock"
    );
    service.retry().unwrap();
    wait(&service, |snapshot| snapshot.connected).await;
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn tunnel_forwards_bytes_and_headers_without_following_redirects_or_accepting_nonlocal_paths()
{
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    let mut server = Server::new(false).await;
    let local = Local::new().await;
    let service = service(store, &server, &local);
    service.start().unwrap();
    wait(&service, |snapshot| snapshot.connected).await;
    server.send(json!({"type":"ping"}));
    assert_eq!(server.receive().await["type"], "pong");
    let body = "Greendale\0 café";
    server.send(json!({"type":"request","stream_id":1,"method":"POST","path":"/echo?class=air%20conditioning","host":"citycollege.example","header":{"Connection":["X-Drop"],"X-Drop":["remove"],"X-Greendale":["preserve"],"Host":["citycollege.example"]},"body":STANDARD.encode(body)}));
    let response = server.receive().await;
    assert_eq!(response["status_code"], 302);
    assert_eq!(
        response["header"]["Set-Cookie"],
        json!(["troy=1", "abed=2"])
    );
    assert!(response["header"].get("Connection").is_none());
    assert!(response["header"].get("X-Response-Hop").is_none());
    assert_eq!(response["header"]["X--Greendale"], json!(["preserve"]));
    let echoed: Value =
        serde_json::from_slice(&STANDARD.decode(response["body"].as_str().unwrap()).unwrap())
            .unwrap();
    assert_eq!(echoed["body"], STANDARD.encode(body));
    assert_eq!(echoed["kept"], "preserve");
    assert!(echoed["dropped"].is_null());
    assert_eq!(echoed["host"], format!("127.0.0.1:{}", local.port));
    for path in [
        "http://citycollege.example/",
        "//citycollege.example/",
        "/%2fcitycollege.example/",
        "greendale",
        "/echo#fragment",
    ] {
        server.send(json!({"type":"request","stream_id":2,"method":"GET","path":path}));
        assert_eq!(server.receive().await["error"], "invalid request path");
    }
    assert_eq!(local.reached.load(Ordering::SeqCst), 1);
    server.send(json!({"type":"request","stream_id":3,"method":"GET","path":"/large"}));
    assert_eq!(
        server.receive().await["error"],
        "local response body too large"
    );
    server.send(json!({"type":"request","stream_id":4,"method":"POST","path":"/body-size","body":STANDARD.encode(vec![b'x'; 16 << 20])}));
    let response = server.receive().await;
    assert_eq!(response["status_code"], 200);
    assert_eq!(
        STANDARD.decode(response["body"].as_str().unwrap()).unwrap(),
        (16 << 20).to_string().as_bytes()
    );
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn tunnel_bounds_in_flight_requests_and_shutdown_cancels_them_without_restarting() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    let mut server = Server::new(false).await;
    let local = Local::new().await;
    let service = service(store, &server, &local);
    service.start().unwrap();
    wait(&service, |snapshot| snapshot.connected).await;
    for stream in 1..=33 {
        server.send(json!({"type":"request","stream_id":stream,"method":"GET","path":"/slow"}));
    }
    let response = server.receive().await;
    assert_eq!(response["stream_id"], 33);
    assert_eq!(response["error"], "local application is busy");
    tokio::time::timeout(std::time::Duration::from_secs(1), service.shutdown())
        .await
        .unwrap()
        .unwrap();
    service.start().unwrap();
    assert!(!service.snapshot().unwrap().connected);
    assert_eq!(server.shared.credentials.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn tunnel_holds_early_requests_until_registration_succeeds() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    let mut server = Server::new(false).await;
    let local = Local::new().await;
    *server.shared.before_registration.lock().unwrap() = (1..=2)
        .map(|stream| json!({"type":"request","stream_id":stream,"method":"GET","path":"/greendale"}))
        .collect();
    server
        .shared
        .hold_registration
        .store(true, Ordering::SeqCst);
    let service = service(store, &server, &local);
    service.start().unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !server.shared.early_sent.load(Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(local.reached.load(Ordering::SeqCst), 0);
    assert!(server.responses.try_recv().is_err());
    assert!(!service.snapshot().unwrap().connected);
    assert!(service.snapshot().unwrap().error.is_empty());
    server.shared.release_registration.notify_one();
    wait(&service, |snapshot| snapshot.connected).await;
    let mut streams = Vec::new();
    for _ in 0..2 {
        let response = server.receive().await;
        assert_eq!(response["status_code"], 302);
        streams.push(response["stream_id"].as_u64().unwrap());
    }
    streams.sort();
    assert_eq!(streams, vec![1, 2]);
    assert_eq!(local.reached.load(Ordering::SeqCst), 2);
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn tunnel_bounds_early_request_count_and_total_bytes_without_forwarding() {
    for large in [false, true] {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("state.db")).unwrap();
        let server = Server::new(false).await;
        let local = Local::new().await;
        let count = if large { 2 } else { 33 };
        let body = if large {
            STANDARD.encode(vec![b'x'; 24 << 20])
        } else {
            String::new()
        };
        *server.shared.before_registration.lock().unwrap() = (1..=count)
            .map(|stream| json!({"type":"request","stream_id":stream,"method":"POST","path":"/greendale","body":body}))
            .collect();
        server
            .shared
            .hold_registration
            .store(true, Ordering::SeqCst);
        let service = service(store, &server, &local);
        service.start().unwrap();
        let failed = wait(&service, |snapshot| snapshot.retry_available).await;
        assert!(
            failed
                .error
                .contains("tunnel registration pending traffic exceeds limit"),
            "{}",
            failed.error
        );
        assert!(!failed.connected);
        assert_eq!(local.reached.load(Ordering::SeqCst), 0);
        server.shared.release_registration.notify_one();
        service.shutdown().await.unwrap();
    }
}
