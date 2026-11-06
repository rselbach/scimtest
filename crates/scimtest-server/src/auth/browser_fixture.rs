use super::*;
use axum::extract::State as AxumState;
use tokio::sync::{mpsc, oneshot};

#[derive(Clone)]
struct Control {
    token: String,
    commands: mpsc::Sender<(Value, oneshot::Sender<Value>)>,
}

async fn control(AxumState(control): AxumState<Control>, request: Request) -> Response {
    if request.method() != "POST"
        || !equal_secret(
            header(request.headers(), "authorization"),
            &format!("Bearer {}", control.token),
        )
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let bytes = axum::body::to_bytes(request.into_body(), 4096)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap();
    let (send, receive) = oneshot::channel();
    control.commands.send((value, send)).await.unwrap();
    axum::Json(receive.await.unwrap()).into_response()
}

#[tokio::test]
#[ignore = "local browser fixture; requires SCIMTEST_HOSTED_BROWSER_READY"]
async fn run_hosted_browser_fixture() {
    let ready = PathBuf::from(
        std::env::var_os("SCIMTEST_HOSTED_BROWSER_READY").expect("fixture output path"),
    );
    let backend =
        std::env::var("SCIMTEST_HOSTED_BROWSER_BACKEND").unwrap_or_else(|_| "Rust".into());
    assert!(matches!(backend.as_str(), "Go" | "Rust"));
    let mut app = Running::configured_provider(false, 1, true, true).await;
    *lock(&app.stub.user) = GitHubUser {
        id: 101,
        login: "rselbach".into(),
    };
    let fixture = if backend == "Go" {
        Some(support::GoFixture::new())
    } else {
        None
    };
    let mut go = if let Some(fixture) = &fixture {
        Some(GoService::start(&mut app, fixture).await)
    } else {
        None
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let token = random_hex(32).unwrap();
    let (commands, mut receive) = mpsc::channel(8);
    let control_url = format!("http://{}", listener.local_addr().unwrap());
    let stop = CancellationToken::new();
    let shutdown = stop.clone();
    let control_app = Router::new().fallback(control).with_state(Control {
        token: token.clone(),
        commands,
    });
    let task = tokio::spawn(async move {
        axum::serve(listener, control_app)
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
            .unwrap();
    });
    std::fs::write(&ready,serde_json::to_vec(&json!({"backend":backend,"base":app.base,"dashboard":format!("http://{}",app.server.0.config.dashboard_domain),"profile":app.profile,"control":control_url,"control_token":token,"state":app.directory.path().join("server.json"),"public_key":support::public_key(41)})).unwrap()).unwrap();
    let mut required = BTreeMap::new();
    let mut peers = Vec::new();
    let timeout = tokio::time::sleep(StdDuration::from_secs(300));
    tokio::pin!(timeout);
    loop {
        let (value, reply) = tokio::select! { value=receive.recv()=>value.expect("browser controller"), _=&mut timeout=>panic!("browser fixture expired") };
        let action = value["action"].as_str().unwrap();
        let result = match action {
            "user" => {
                *lock(&app.stub.user) = GitHubUser {
                    id: value["id"].as_i64().unwrap(),
                    login: value["login"].as_str().unwrap().into(),
                };
                json!({"ok":true})
            }
            "enroll" => {
                let seed = u8::try_from(value["seed"].as_u64().unwrap()).unwrap();
                let (socket, message) = app.dial(seed, "", "", seed).await;
                drop(socket);
                let message = decode(message);
                assert_eq!(message.kind, "enrollment_required");
                let result = json!({"url":message.enrollment_url,"handoff":message.enrollment_browser_handoff_url,"code":message.enrollment_verification_code,"instance":app.binding(seed,"").instance});
                required.insert(seed, message);
                result
            }
            "connect" => {
                let seed = u8::try_from(value["seed"].as_u64().unwrap()).unwrap();
                let (mut socket, message) = app
                    .dial(seed, "", &required[&seed].enrollment_device_code, seed)
                    .await;
                let message = decode(message);
                assert_eq!(message.kind, "tunnel_registered");
                peers.push(tokio::spawn(async move {
                    while let Some(message) = socket.next().await {
                        match message {
                            Ok(tungstenite::Message::Ping(value)) => socket
                                .send(tungstenite::Message::Pong(value))
                                .await
                                .unwrap(),
                            Ok(tungstenite::Message::Close(_)) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                }));
                json!({"url":message.public_url,"login":message.github_login,"instance":app.binding(seed,"").instance})
            }
            "snapshot" => {
                let metrics = app
                    .request(Method::GET, "/api/metrics")
                    .send()
                    .await
                    .unwrap()
                    .json::<Value>()
                    .await
                    .unwrap();
                json!({"profiles":saved(&app).profiles().unwrap(),"metrics":metrics})
            }
            "stop" => json!({"stopped":true}),
            _ => panic!("unknown browser fixture action"),
        };
        reply.send(result).unwrap();
        if action == "stop" {
            break;
        }
    }
    stop.cancel();
    task.await.unwrap();
    for peer in peers {
        peer.abort();
    }
    finish(&mut app, go.as_mut()).await;
    println!("Hosted {backend} browser fixture stopped");
}
