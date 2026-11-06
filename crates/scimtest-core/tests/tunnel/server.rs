use axum::{
    Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{CloseFrame, Message, WebSocket},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
    },
};
use tokio::sync::mpsc;

pub enum Command {
    Json(Value),
    Close(u16, String),
}
pub struct Shared {
    pub base: String,
    pub enrollment: bool,
    pub approved: AtomicBool,
    pub poll_error: AtomicU16,
    pub polls: AtomicUsize,
    pub credentials: Mutex<Vec<Value>>,
    pub login: Mutex<String>,
    pub public_url: Mutex<String>,
    pub before_registration: Mutex<Vec<Value>>,
    pub early_sent: AtomicBool,
    pub hold_registration: AtomicBool,
    pub release_registration: tokio::sync::Notify,
    known: Mutex<HashSet<String>>,
    commands: tokio::sync::Mutex<mpsc::UnboundedReceiver<Command>>,
    responses: mpsc::UnboundedSender<Value>,
}
pub struct Server {
    pub shared: Arc<Shared>,
    pub commands: mpsc::UnboundedSender<Command>,
    pub responses: mpsc::UnboundedReceiver<Value>,
    task: tokio::task::JoinHandle<()>,
}
impl Server {
    pub async fn new(enrollment: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (send_commands, commands) = mpsc::unbounded_channel();
        let (responses, receive_responses) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            base,
            enrollment,
            approved: AtomicBool::new(false),
            poll_error: AtomicU16::new(0),
            polls: AtomicUsize::new(0),
            credentials: Mutex::new(Vec::new()),
            login: Mutex::new("troy-barnes".into()),
            public_url: Mutex::new("https://scimtest.example/greendale".into()),
            before_registration: Mutex::new(Vec::new()),
            early_sent: AtomicBool::new(false),
            hold_registration: AtomicBool::new(false),
            release_registration: tokio::sync::Notify::new(),
            known: Mutex::new(HashSet::new()),
            commands: tokio::sync::Mutex::new(commands),
            responses,
        });
        let app = Router::new()
            .route("/api/connect", get(upgrade))
            .route("/enroll/status", post(status))
            .with_state(shared.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            shared,
            commands: send_commands,
            responses: receive_responses,
            task,
        }
    }
    pub fn send(&self, value: Value) {
        self.commands.send(Command::Json(value)).unwrap();
    }
    pub async fn receive(&mut self) -> Value {
        tokio::time::timeout(std::time::Duration::from_secs(5), self.responses.recv())
            .await
            .unwrap()
            .unwrap()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn upgrade(State(state): State<Arc<Shared>>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| connection(state, socket))
}
async fn read(socket: &mut WebSocket) -> Option<Value> {
    match socket.recv().await {
        Some(Ok(Message::Text(text))) => Some(serde_json::from_str(&text).unwrap()),
        _ => None,
    }
}
async fn send(socket: &mut WebSocket, value: Value) {
    socket
        .send(Message::Text(value.to_string().into()))
        .await
        .unwrap();
}
async fn connection(state: Arc<Shared>, mut socket: WebSocket) {
    let Some(registration) = read(&mut socket).await else {
        return;
    };
    assert_eq!(registration["type"], "register_tunnel");
    send(&mut socket,json!({"type":"application_challenge","enrollment_supported":true,"challenge":"greendale-challenge"})).await;
    let Some(signature) = read(&mut socket).await else {
        return;
    };
    assert_eq!(signature["type"], "application_signature");
    let public = registration["instance_public_key"].as_str().unwrap();
    let key =
        VerifyingKey::from_bytes(&STANDARD.decode(public).unwrap().try_into().unwrap()).unwrap();
    let payload = format!(
        "scimtest-server-instance-registration-v1\n{}\n{public}\n{}\ngreendale-challenge",
        registration["application_profile_id"].as_str().unwrap(),
        registration["instance_id"].as_str().unwrap()
    );
    let signed = Signature::from_slice(
        &STANDARD
            .decode(signature["signature"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    key.verify(payload.as_bytes(), &signed).unwrap();
    state.credentials.lock().unwrap().push(json!({"instance_id":registration["instance_id"],"public_key":public,"grant":signature["enrollment_grant"]}));
    let enrolled = state.known.lock().unwrap().contains(public);
    if state.enrollment && !enrolled && signature["enrollment_grant"] != "greendale-device-secret" {
        send(&mut socket,json!({"type":"enrollment_required","enrollment_url":format!("{}/enroll?code=greendale",state.base),"enrollment_browser_handoff_url":format!("{}/enroll/browser?handoff=one-use",state.base),"enrollment_status_url":format!("{}/enroll/status",state.base),"enrollment_device_code":"greendale-device-secret","enrollment_verification_code":"GREEN-DALE","enrollment_poll_seconds":1})).await;
        return;
    }
    state.known.lock().unwrap().insert(public.into());
    let early = std::mem::take(&mut *state.before_registration.lock().unwrap());
    for value in early {
        if socket
            .send(Message::Text(value.to_string().into()))
            .await
            .is_err()
        {
            return;
        }
    }
    state.early_sent.store(true, Ordering::SeqCst);
    if state.hold_registration.load(Ordering::SeqCst) {
        state.release_registration.notified().await;
    }
    let url = state.public_url.lock().unwrap().clone();
    let login = state.login.lock().unwrap().clone();
    if socket.send(Message::Text(json!({"type":"tunnel_registered","tunnel_id":"greendale-tunnel","public_url":url,"client_ip":"203.0.113.7","github_user_id":42,"github_login":login}).to_string().into())).await.is_err() {
        return;
    }
    loop {
        tokio::select! {
            command=async { state.commands.lock().await.recv().await }=>match command {
                Some(Command::Json(value))=>send(&mut socket,value).await,
                Some(Command::Close(code,reason))=> { socket.send(Message::Close(Some(CloseFrame { code,reason:reason.into() }))).await.unwrap();break; }
                None=>break,
            },
            response=read(&mut socket)=>match response {
                Some(value)=> { if state.responses.send(value).is_err() { break; } },
                None=>break,
            },
        }
    }
}
async fn status(State(state): State<Arc<Shared>>, headers: HeaderMap) -> Response {
    assert_eq!(headers["authorization"], "Bearer greendale-device-secret");
    assert_eq!(headers["cache-control"], "no-store");
    state.polls.fetch_add(1, Ordering::SeqCst);
    let error = state.poll_error.swap(0, Ordering::SeqCst);
    if error != 0 {
        return StatusCode::from_u16(error).unwrap().into_response();
    }
    axum::Json(json!({"status":if state.approved.load(Ordering::SeqCst) { "approved" } else { "pending" }})).into_response()
}
