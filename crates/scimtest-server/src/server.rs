use crate::{
    config::Config, lock, network, registration::RegistrationPool, store::Store, tunnel::Tunnel,
};
use anyhow::Result;
use axum::{
    Extension, Router,
    body::Body,
    extract::{ConnectInfo, Request, State as AxumState},
    http::{HeaderValue, StatusCode},
    response::Response,
};
use ipnet::IpNet;
use percent_encoding::percent_decode_str;
use serde_json::json;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use tokio::sync::RwLock;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

#[derive(Clone)]
pub struct Server(pub(crate) Arc<State>);

pub(crate) struct State {
    pub config: Config,
    pub trusted: Vec<IpNet>,
    pub store: Arc<Store>,
    pub github: crate::auth::GitHubClient,
    pub enrollment: Mutex<crate::enrollment::EnrollmentState>,
    pub templates: minijinja::Environment<'static>,
    pub profile_gate: Arc<RwLock<()>>,
    pub tunnels: Mutex<HashMap<String, Arc<Tunnel>>>,
    pub registrations: Arc<RegistrationPool>,
    pub tasks: TaskTracker,
    pub shutdown: CancellationToken,
    pub next_stream: AtomicU64,
    pub requests_total: AtomicU64,
    pub tunnels_total: AtomicU64,
}

impl Server {
    pub fn new(config: Config) -> Result<Self> {
        let (config, trusted) = config.normalize()?;
        let store = Arc::new(Store::open(&config.data_path)?);
        Ok(Self(Arc::new(State {
            config,
            trusted,
            store,
            github: crate::auth::GitHubClient::new()?,
            enrollment: Mutex::new(crate::enrollment::EnrollmentState::default()),
            templates: crate::dashboard::templates()?,
            profile_gate: Arc::new(RwLock::new(())),
            tunnels: Mutex::new(HashMap::new()),
            registrations: Arc::new(RegistrationPool::default()),
            tasks: TaskTracker::new(),
            shutdown: CancellationToken::new(),
            next_stream: AtomicU64::new(0),
            requests_total: AtomicU64::new(0),
            tunnels_total: AtomicU64::new(0),
        })))
    }

    pub fn store(&self) -> &Store {
        &self.0.store
    }

    pub(crate) fn router(&self) -> Router {
        Router::new().fallback(dispatch).with_state(self.0.clone())
    }
}

impl State {
    pub fn public_host(&self, host: &str) -> bool {
        network::host_allowed(host, &self.config.domain)
    }
    pub fn dashboard_host(&self, host: &str) -> bool {
        network::host_allowed(host, &self.config.dashboard_domain)
    }

    pub fn tunnel_for(&self, escaped_path: &str) -> Option<Arc<Tunnel>> {
        let path = percent_decode_str(escaped_path).decode_utf8_lossy();
        let path = path.strip_prefix('/')?;
        let id = path.split('/').next()?;
        lock(&self.tunnels).get(id).cloned()
    }

    pub fn request_finished(
        &self,
        method: &str,
        path: &str,
        peer: SocketAddr,
        status: u16,
        start: Instant,
    ) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        if !self.config.logs {
            return;
        }
        if self.config.log_format == "json" {
            eprintln!(
                "{}",
                json!({"msg":"request","method":method,"path":path,"remote":peer.to_string(),"status":status,"duration":start.elapsed().as_nanos()})
            );
            return;
        }
        eprintln!(
            "request method={method} path={path:?} remote={peer} status={status} duration={:?}",
            start.elapsed()
        );
    }
}

async fn dispatch(
    AxumState(state): AxumState<Arc<State>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Extension(deadline): Extension<Arc<crate::runtime::deadline::WriteDeadline>>,
    request: Request,
) -> Response {
    deadline.start();
    let start = Instant::now();
    let path = request.uri().path().to_owned();
    let method = request.method().to_string();
    let host = request
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok())
        .or_else(|| {
            request
                .uri()
                .authority()
                .map(|authority| authority.as_str())
        })
        .unwrap_or("")
        .to_owned();
    let tunnel = state
        .public_host(&host)
        .then(|| state.tunnel_for(&path))
        .flatten();
    let server_page = if state.public_host(&host) {
        tunnel.is_none()
    } else {
        state.dashboard_host(&host)
    };
    let mut response = match path.as_str() {
        "/healthz" | "/ready" => json_response(json!({"status":"ok"})),
        "/api/metrics" if state.dashboard_host(&host) => json_response(json!({
            "requests_total":state.requests_total.load(Ordering::Relaxed),
            "tunnels_active":lock(&state.tunnels).len(),"tunnels_total":state.tunnels_total.load(Ordering::Relaxed)})),
        path if path == state.config.connect_path => {
            if !state.public_host(&host) {
                not_found()
            } else {
                crate::registration::upgrade(state.clone(), request, peer, start).await
            }
        }
        "/api/enroll/status" if state.public_host(&host) => state.enrollment_status(&request),
        "/login/github" if state.dashboard_host(&host) => {
            state.begin_oauth(&request, peer, None).unwrap_or_else(|_| {
                error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not create login state",
                )
            })
        }
        "/auth/github/callback" if state.dashboard_host(&host) => {
            state.oauth_callback(request).await
        }
        "/enroll" if state.dashboard_host(&host) => state.enrollment_page(request, peer).await,
        "/enroll/browser" if state.dashboard_host(&host) => {
            state.enrollment_handoff(&request, peer)
        }
        "/enroll/replace" if state.dashboard_host(&host) => state.replace_enrollment(request).await,
        path if state.dashboard_host(&host)
            && (path == "/logout"
                || path == "/dashboard"
                || crate::config::MANAGEMENT_PATHS.contains(&path)
                    && path.starts_with("/dashboard/")) =>
        {
            state.dashboard(request).await
        }
        "/" if state.dashboard_host(&host) => {
            let mut response = text_response(
                StatusCode::OK,
                "text/html; charset=utf-8",
                include_str!("../../../internal/server/templates/landing.html"),
            );
            response
                .headers_mut()
                .insert("cache-control", HeaderValue::from_static("no-store"));
            response.headers_mut().insert(
                "content-security-policy",
                HeaderValue::from_static(
                    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
                ),
            );
            response
        }
        "/" if state.public_host(&host) => {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::FOUND;
            if let Ok(location) = HeaderValue::from_str(&format!(
                "{}://{}/",
                state.config.public_scheme, state.config.dashboard_domain
            )) {
                response.headers_mut().insert("location", location);
            }
            response
        }
        _ => {
            if let Some(tunnel) = tunnel {
                crate::forwarding::forward(state.clone(), tunnel, request, peer, &host).await
            } else {
                not_found()
            }
        }
    };
    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        return response;
    }
    if server_page {
        for (key, value) in [
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
            ("referrer-policy", "strict-origin-when-cross-origin"),
            (
                "permissions-policy",
                "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
            ),
        ] {
            response
                .headers_mut()
                .entry(key)
                .or_insert(HeaderValue::from_static(value));
        }
        if state.config.public_scheme == "https" || state.config.behind_proxy {
            response.headers_mut().insert(
                "strict-transport-security",
                HeaderValue::from_static("max-age=63072000"),
            );
        }
    }
    state.request_finished(&method, &path, peer, response.status().as_u16(), start);
    response
}

pub(crate) fn json_response(value: serde_json::Value) -> Response {
    text_response(StatusCode::OK, "application/json", format!("{value}\n"))
}

pub(crate) fn text_response(
    status: StatusCode,
    content_type: &'static str,
    text: impl Into<Body>,
) -> Response {
    let mut response = Response::new(text.into());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static(content_type));
    response
}

pub(crate) fn error(status: StatusCode, message: &str) -> Response {
    let mut response = text_response(status, "text/plain; charset=utf-8", format!("{message}\n"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

pub(crate) fn not_found() -> Response {
    error(StatusCode::NOT_FOUND, "404 page not found")
}
