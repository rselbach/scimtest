use super::{
    Enrollment,
    client::{Client, Event, Registration},
};
use crate::{Error, Store};
use serde::Serialize;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use url::Url;

#[derive(Clone)]
pub struct Config {
    pub server_base_url: String,
    pub application_profile_id: String,
    pub require_account: bool,
}
impl Config {
    pub fn build_profile() -> Result<Option<Self>, Error> {
        let profile = option_env!("SCIMTEST_TUNNEL_PROFILE_ID")
            .unwrap_or_default()
            .trim();
        let required = option_env!("SCIMTEST_RELEASE_PROFILE_REQUIRED")
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("true"));
        if profile.is_empty() && !required {
            return Ok(None);
        }
        let config = Self {
            server_base_url: option_env!("SCIMTEST_TUNNEL_SERVER")
                .unwrap_or("https://scimtest.rselbach.com")
                .into(),
            application_profile_id: profile.into(),
            require_account: true,
        };
        config.validate()?;
        Ok(Some(config))
    }
    pub(crate) fn validate(&self) -> Result<Url, Error> {
        if self.application_profile_id.len() != 32
            || !self
                .application_profile_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Error::Validation(
                "tunnel application profile id must be 32 lowercase hexadecimal characters".into(),
            ));
        }
        let mut url = Url::parse(self.server_base_url.trim())
            .map_err(|_| Error::Validation("invalid tunnel server URL".into()))?;
        let scheme = match url.scheme() {
            "http" => "ws",
            "https" => "wss",
            _ => {
                return Err(Error::Validation(
                    "tunnel server URL must use HTTP or HTTPS".into(),
                ));
            }
        };
        if url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::Validation("invalid tunnel server URL".into()));
        }
        url.set_scheme(scheme)
            .map_err(|_| Error::Validation("invalid tunnel server URL".into()))?;
        url.set_path(&format!("{}/api/connect", url.path().trim_end_matches('/')));
        Ok(url)
    }
}
#[derive(Clone, Default, Serialize)]
pub struct Snapshot {
    pub supported: bool,
    pub starting: bool,
    pub connected: bool,
    pub retry_available: bool,
    pub error: String,
    pub enrollment_url: String,
    pub enrollment_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    #[serde(skip)]
    pub tunnel_id: String,
    #[serde(skip)]
    pub github_user_id: i64,
    #[serde(skip)]
    pub github_login: String,
}
impl Snapshot {
    pub fn account_error(&self, required: bool) -> String {
        if self.state() == "unavailable" {
            return "This build has no application profile for GitHub sign-in.".into();
        }
        let error = human_error(&self.error);
        if required {
            return error.replace(
                "; scimtest keeps working locally",
                "; sign-in is required before the desktop app can unlock",
            );
        }
        error
    }
    pub fn state(&self) -> &'static str {
        if self.connected {
            return "connected";
        }
        if !self.enrollment_url.is_empty() {
            return "authorizing";
        }
        if !self.error.is_empty() {
            return "failed";
        }
        if self.supported {
            return "connecting";
        }
        "unavailable"
    }
}
pub struct PublicEndpoint {
    pub url: String,
    pub prefix: String,
    pub client_ip: String,
}
#[derive(Clone)]
pub struct Service(Arc<Inner>);
struct Inner {
    store: Store,
    config: Option<Config>,
    local_port: u16,
    runtime: Option<tokio::runtime::Handle>,
    revision: watch::Sender<u64>,
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    snapshot: Snapshot,
    authorization_url: String,
    generation: u64,
    worker: Option<Worker>,
    closing: bool,
    resetting: bool,
}
struct Worker {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}
impl Service {
    pub fn new(store: Store, config: Option<Config>, local_port: u16) -> Result<Self, Error> {
        if let Some(config) = &config {
            config.validate()?;
            if local_port == 0 {
                return Err(Error::Validation("a local tunnel port is required".into()));
            }
        }
        Ok(Self::initialize(store, config, local_port))
    }
    pub fn unavailable(store: Store) -> Self {
        Self::initialize(store, None, 0)
    }
    fn initialize(store: Store, config: Option<Config>, local_port: u16) -> Self {
        let (revision, _) = watch::channel(0);
        let supported = config.is_some();
        Self(Arc::new(Inner {
            store,
            config,
            local_port,
            runtime: tokio::runtime::Handle::try_current().ok(),
            revision,
            state: Mutex::new(State {
                snapshot: Snapshot {
                    supported,
                    ..Default::default()
                },
                ..Default::default()
            }),
        }))
    }
    fn state(&self) -> Result<MutexGuard<'_, State>, Error> {
        self.0.state.lock().map_err(|_| Error::Lock)
    }
    fn changed(&self) {
        self.0
            .revision
            .send_modify(|value| *value = value.wrapping_add(1));
    }
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.revision.subscribe()
    }
    pub fn required(&self) -> bool {
        self.0
            .config
            .as_ref()
            .is_some_and(|config| config.require_account)
    }
    pub fn snapshot(&self) -> Result<Snapshot, Error> {
        Ok(self.state()?.snapshot.clone())
    }
    pub fn unlocked(&self) -> Result<bool, Error> {
        Ok(!self.required() || self.state()?.snapshot.connected)
    }
    pub fn public_endpoint(&self) -> Result<Option<PublicEndpoint>, Error> {
        let state = self.state()?;
        let Some(url) = &state.snapshot.public_url else {
            return Ok(None);
        };
        Ok(Some(PublicEndpoint {
            url: url.clone(),
            prefix: public_prefix(url)?,
            client_ip: state.snapshot.client_ip.clone().unwrap_or_default(),
        }))
    }
    pub fn effective_base(&self, local: &str) -> Result<String, Error> {
        if let Some(endpoint) = self.public_endpoint()? {
            return Ok(endpoint.url);
        }
        let config = self.0.store.global_config()?;
        if !config.idp_base_url.is_empty() {
            return Ok(config.idp_base_url);
        }
        Ok(local.to_owned())
    }
    pub fn account(&self) -> Result<Value, Error> {
        let snapshot = self.snapshot()?;
        let error = snapshot.account_error(self.required());
        Ok(
            json!({"required":self.required(),"state":snapshot.state(),"error":error,"linked":self.required() && snapshot.connected,
            "login":if self.required() && snapshot.connected && snapshot.github_user_id>0 { snapshot.github_login } else { String::new() },"enrollment_url":snapshot.enrollment_url,"enrollment_code":snapshot.enrollment_code}),
        )
    }
    pub fn authorization_url(&self) -> Result<String, Error> {
        if !self.required() {
            return Err(Error::NotFound("account sign-in"));
        }
        let url = self.state()?.authorization_url.clone();
        if url.is_empty() {
            return Err(Error::Conflict(
                "GitHub authorization is not ready; try again".into(),
            ));
        }
        Ok(url)
    }
    pub fn start(&self) -> Result<(), Error> {
        let Some(config) = self.0.config.clone() else {
            return Ok(());
        };
        let runtime = self.0.runtime.as_ref().ok_or_else(|| {
            Error::Validation("tunnel connections require an async runtime".into())
        })?;
        let mut state = self.state()?;
        if state.closing || state.resetting || state.worker.is_some() {
            return Ok(());
        }
        state.generation = state.generation.wrapping_add(1);
        let generation = state.generation;
        state.snapshot.starting = true;
        state.snapshot.error.clear();
        state.snapshot.retry_available = false;
        state.snapshot.enrollment_url.clear();
        state.snapshot.enrollment_code.clear();
        state.authorization_url.clear();
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let service = self.clone();
        let task = runtime.spawn(async move {
            service.run(generation, config, task_cancel).await;
        });
        state.worker = Some(Worker { cancel, task });
        self.changed();
        Ok(())
    }
    pub fn retry(&self) -> Result<(), Error> {
        if !self.state()?.snapshot.retry_available {
            return Ok(());
        }
        self.start()
    }
    async fn run(&self, generation: u64, config: Config, cancel: CancellationToken) {
        let identity = self.0.store.clone();
        let initialized =
            tokio::task::spawn_blocking(move || identity.installation_identity()).await;
        let outcome = match initialized {
            Ok(Ok(identity)) => match config.validate() {
                Ok(server) => Ok((server, identity)),
                Err(error) => Err(error.to_string()),
            },
            Ok(Err(error)) => Err(error.to_string()),
            Err(error) => Err(error.to_string()),
        };
        if cancel.is_cancelled() {
            return;
        }
        let (server, identity) = match outcome {
            Ok(value) => value,
            Err(error) => {
                self.finish(generation, error);
                return;
            }
        };
        let (sender, mut events) = mpsc::unbounded_channel();
        let client = match Client::new(
            server,
            config.application_profile_id,
            identity,
            self.0.local_port,
            sender,
            cancel.clone(),
        ) {
            Ok(client) => client,
            Err(error) => {
                self.finish(generation, error.message);
                return;
            }
        };
        let mut client = Box::pin(client.run());
        let mut timer = Box::pin(tokio::time::sleep(Duration::from_secs(20)));
        let mut registered = false;
        let mut timeout = Duration::from_secs(20);
        loop {
            tokio::select! {
                _=cancel.cancelled()=>break,
                result=&mut client=> { self.finish(generation,result.err().map(|error| format!("start automatic tunnel: {error}")).unwrap_or_else(|| "tunnel connection closed".into()));break; }
                event=events.recv()=> {
                    let result=match event {
                        Some(Event::Registered(registration))=> { registered=true;self.registered(generation,registration) },
                        Some(Event::Enrollment(enrollment))=> {
                            timeout=Duration::from_secs(11*60);timer.as_mut().reset(Instant::now()+timeout);
                            self.enrollment(generation,enrollment)
                        }
                        None=>Ok(()),
                    };
                    if let Err(error)=result { cancel.cancel();self.finish(generation,error.to_string());break; }
                }
                _=&mut timer, if !registered=> {
                    cancel.cancel();self.finish(generation,format!("timed out after {}s waiting for tunnel registration",timeout.as_secs()));break;
                }
            }
        }
    }
    fn registered(&self, generation: u64, registration: Registration) -> Result<(), Error> {
        let url = registration
            .public_url
            .trim()
            .trim_end_matches('/')
            .to_owned();
        public_prefix(&url)?;
        let mut state = self.state()?;
        if state.generation != generation || state.closing {
            return Ok(());
        }
        state.snapshot.connected = true;
        state.snapshot.starting = false;
        state.snapshot.retry_available = false;
        state.snapshot.error.clear();
        state.snapshot.public_url = Some(url);
        state.snapshot.client_ip = Some(registration.client_ip.trim().into());
        state.snapshot.tunnel_id = registration.tunnel_id;
        state.snapshot.github_user_id = registration.github_user_id;
        state.snapshot.github_login = registration.github_login.trim().into();
        state.snapshot.enrollment_url.clear();
        state.snapshot.enrollment_code.clear();
        state.authorization_url.clear();
        self.changed();
        Ok(())
    }
    fn enrollment(&self, generation: u64, enrollment: Enrollment) -> Result<(), Error> {
        let mut state = self.state()?;
        if state.generation != generation || state.closing {
            return Ok(());
        }
        state.authorization_url = if self.required() {
            enrollment.authorization_url()
        } else {
            enrollment.url
        };
        state.snapshot.enrollment_url = desktop_url(&state.authorization_url);
        state.snapshot.enrollment_code = enrollment.verification_code;
        self.changed();
        Ok(())
    }
    fn finish(&self, generation: u64, error: String) {
        let Ok(mut state) = self.state() else {
            return;
        };
        if state.generation != generation || state.closing {
            return;
        }
        state.worker.take();
        state.snapshot.connected = false;
        state.snapshot.starting = false;
        state.snapshot.public_url = None;
        state.snapshot.client_ip = None;
        state.snapshot.tunnel_id.clear();
        state.snapshot.github_user_id = 0;
        state.snapshot.github_login.clear();
        state.snapshot.enrollment_url.clear();
        state.snapshot.enrollment_code.clear();
        state.authorization_url.clear();
        state.snapshot.error = error;
        state.snapshot.retry_available = !state.snapshot.error.is_empty();
        self.changed();
    }
    pub async fn logout(&self) -> Result<(), Error> {
        if !self.required() {
            return Err(Error::NotFound("account sign-in"));
        }
        let service = self.clone();
        let worker = tokio::task::spawn_blocking(move || {
            let mut state = service.state()?;
            if state.closing {
                return Err(Error::Conflict("scimtest is shutting down".into()));
            }
            if state.resetting {
                return Err(Error::Conflict(
                    "GitHub account sign-out is already in progress".into(),
                ));
            }
            state.resetting = true;
            let rotated = service.0.store.rotate_installation_identity();
            if let Err(error) = rotated {
                state.resetting = false;
                return Err(error);
            }
            state.generation = state.generation.wrapping_add(1);
            let worker = state.worker.take();
            state.snapshot = Snapshot {
                supported: service.0.config.is_some(),
                ..Default::default()
            };
            state.authorization_url.clear();
            service.changed();
            Ok(worker)
        })
        .await
        .map_err(|error| Error::Io(std::io::Error::other(error)))??;
        let stopped = stop(worker).await;
        self.state()?.resetting = false;
        stopped?;
        self.start()
    }
    pub(crate) fn cancel(&self) -> Result<(), Error> {
        {
            let mut state = self.state()?;
            state.closing = true;
            state.generation = state.generation.wrapping_add(1);
            state.snapshot.connected = false;
            state.snapshot.public_url = None;
            state.snapshot.client_ip = None;
            if let Some(worker) = &state.worker {
                worker.cancel.cancel();
            }
        }
        self.changed();
        Ok(())
    }
    pub async fn shutdown(&self) -> Result<(), Error> {
        self.cancel()?;
        let worker = self.state()?.worker.take();
        stop(worker).await
    }
}
async fn stop(worker: Option<Worker>) -> Result<(), Error> {
    if let Some(worker) = worker {
        worker.cancel.cancel();
        worker
            .task
            .await
            .map_err(|error| Error::Io(std::io::Error::other(error)))?;
    }
    Ok(())
}
fn public_prefix(value: &str) -> Result<String, Error> {
    let invalid = || Error::Validation("tunnel returned an invalid public URL".into());
    let url = Url::parse(value).map_err(|_| invalid())?;
    let path = percent_encoding::percent_decode_str(url.path())
        .decode_utf8()
        .map_err(|_| invalid())?;
    let path = path.trim_end_matches('/');
    if !["http", "https"].contains(&url.scheme())
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || path.is_empty()
        || !path.starts_with('/')
        || path[1..].contains('/')
    {
        return Err(invalid());
    }
    Ok(path.into())
}
fn desktop_url(value: &str) -> String {
    let Ok(mut url) = Url::parse(value) else {
        return value.into();
    };
    let mut query = url
        .query_pairs()
        .filter(|(key, _)| key != "presentation")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    query.push(("presentation".into(), "desktop".into()));
    url.query_pairs_mut().clear().extend_pairs(query);
    url.into()
}
fn human_error(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    if lower.contains("installation revoked") {
        return "the tunnel operator revoked this installation; scimtest keeps working locally"
            .into();
    }
    if lower.contains("too many new installations") {
        return "the tunnel server is limiting new installations from your network; try again later".into();
    }
    if lower.contains("bad handshake") || lower.contains("403") {
        return "the tunnel server rejected this build's identity; upgrading scimtest usually fixes this".into();
    }
    if lower.contains("context deadline exceeded") || lower.contains("timeout") {
        return "the tunnel server did not respond in time; scimtest keeps working locally".into();
    }
    if lower.contains("connection refused")
        || lower.contains("no such host")
        || lower.contains("dial tcp")
        || lower.contains("dns error")
    {
        return "could not reach the tunnel server; check your network connection".into();
    }
    value.into()
}
