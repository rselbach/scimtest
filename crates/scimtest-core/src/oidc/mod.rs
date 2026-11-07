mod authorize;
mod backchannel;
mod chooser;
mod claims;
pub use chooser::{ChooserOptions, ChooserSession};
pub(crate) fn login_hint_user<'a>(directory: &'a Directory, hint: &str) -> Option<&'a str> {
    chooser::login_user(directory, hint).map(|user| user.id.as_str())
}
mod lifecycle;
pub use lifecycle::{JoinerInput, LifecycleMessage, LifecycleRun, LifecycleStep, MoverInput};
pub(crate) mod faults;
mod playground;
mod resilience;
pub use resilience::{ResiliencePreset, ResilienceRun};
mod saml;
mod saml_logout;
mod sessions;
pub use playground::{PlaygroundInput, playground};
pub use saml::SamlAuthorization;
pub use saml_logout::SamlLogout;
mod tokens;
pub use sessions::Logout;

use crate::{
    Error, Store,
    model::{Directory, User},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};

pub use authorize::Authorization;
pub use claims::{discovery, object_id};
pub use faults::Faults;
pub type Parameters = HashMap<String, String>;

#[derive(Debug)]
pub struct ProtocolError {
    pub status: u16,
    pub code: String,
    pub description: String,
    pub basic_challenge: bool,
    pub retry_after: Option<String>,
}
impl ProtocolError {
    pub fn new(code: &str, description: &str) -> Self {
        Self {
            status: 400,
            code: code.into(),
            description: description.into(),
            basic_challenge: false,
            retry_after: None,
        }
    }
    fn unauthorized(code: &str, description: &str) -> Self {
        Self {
            status: 401,
            ..Self::new(code, description)
        }
    }
}
impl From<Error> for ProtocolError {
    fn from(error: Error) -> Self {
        let status = match error {
            Error::NotFound(_) => 404,
            Error::Validation(_) => 400,
            Error::Conflict(_) => 409,
            _ => 500,
        };
        Self {
            status,
            ..Self::new("server_error", &error.to_string())
        }
    }
}
type Result<T> = std::result::Result<T, ProtocolError>;

#[derive(Clone)]
pub struct Identity(Arc<Inner>);
struct Inner {
    store: Store,
    diagnostics: crate::diagnostics::Diagnostics,
    memory: Mutex<Memory>,
    revision: tokio::sync::watch::Sender<u64>,
    runtime: Option<tokio::runtime::Handle>,
}
#[derive(Default)]
struct Memory {
    ended: Option<tokio::sync::mpsc::UnboundedSender<Session>>,
    revision: Option<tokio::sync::watch::Sender<u64>>,
    logout_results: HashMap<String, Vec<Value>>,
    codes: HashMap<String, Grant>,
    access: HashMap<String, Access>,
    refresh: HashMap<String, Refresh>,
    sessions: HashMap<String, Session>,
    flows: HashMap<String, Vec<Value>>,
    inspections: HashMap<String, Vec<Value>>,
    saml_inspections: HashMap<String, Vec<Value>>,
    saml_logouts: HashMap<String, Vec<Value>>,
    saml_deliveries: HashMap<String, (String, DateTime<Utc>, crate::saml::OutboundMessage)>,
    faults: HashMap<String, Faults>,
    resilience: HashMap<String, ResilienceRun>,
    redeeming: HashMap<String, String>,
    lifecycle: HashMap<String, Vec<LifecycleRun>>,
}
#[derive(Clone, Default)]
struct Grant {
    environment: String,
    client: String,
    user: String,
    redirect: String,
    nonce: String,
    scope: String,
    challenge: String,
    authn: Authn,
    session: String,
    grant_id: String,
    expires: DateTime<Utc>,
    faults: Faults,
}
#[derive(Clone, Default)]
struct Authn {
    time: DateTime<Utc>,
    strength: String,
    context: String,
}
impl Authn {
    fn add_claims(&self, claims: &mut Value, skew: Duration) {
        claims["auth_time"] = json!((self.time + skew).timestamp());
        claims["acr"] = json!(self.context);
        claims["amr"] = if self.strength == "mfa" {
            json!(["pwd", "otp", "mfa"])
        } else {
            json!(["pwd"])
        };
    }
}
#[derive(Clone)]
struct Access {
    grant: Grant,
    issued: DateTime<Utc>,
    expires: DateTime<Utc>,
    audience: String,
}
#[derive(Clone)]
struct Refresh {
    grant: Grant,
    issued: DateTime<Utc>,
    expires: DateTime<Utc>,
}
#[derive(Clone)]
struct Session {
    id: String,
    environment: String,
    user: String,
    label: String,
    authn: Authn,
    started: DateTime<Utc>,
    protocols: Vec<String>,
    issuer: String,
    saml_index: String,
    saml_name_id: String,
    saml_name_id_format: String,
}

impl Identity {
    pub fn new(store: Store) -> Self {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let (revision, _) = tokio::sync::watch::channel(0);
        let identity = Self(Arc::new(Inner {
            store,
            diagnostics: crate::diagnostics::Diagnostics::default(),
            revision: revision.clone(),
            runtime: tokio::runtime::Handle::try_current().ok(),
            memory: Mutex::new(Memory {
                ended: Some(sender),
                revision: Some(revision.clone()),
                ..Default::default()
            }),
        }));
        identity.start_sessions(receiver);
        identity
    }

    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.0.revision.subscribe()
    }
    pub fn diagnostics(&self) -> crate::diagnostics::Diagnostics {
        self.0.diagnostics.clone()
    }
    fn memory(&self) -> Result<MutexGuard<'_, Memory>> {
        self.0.memory.lock().map_err(|_| Error::Lock.into())
    }
    pub fn directory(&self, slug: &str) -> Result<Directory> {
        let directory = self.0.store.directory_by_slug(slug)?;
        if !directory.environment.settings.supports_oidc() {
            return Err(ProtocolError {
                status: 404,
                ..ProtocolError::new("not_found", "OIDC is not enabled")
            });
        }
        Ok(directory)
    }
    pub fn record_failure(&self, slug: &str, stage: &str, detail: &str) -> Result<()> {
        let directory = self.directory(slug)?;
        let mut memory = self.memory()?;
        memory.event(&directory.environment.id, stage, "", detail);
        if let Some(event) = memory
            .flows
            .get_mut(&directory.environment.id)
            .and_then(|events| events.first_mut())
        {
            event["Outcome"] = json!("failed");
        }
        Ok(())
    }
    pub fn flows(&self, id: &str) -> Result<Vec<Value>> {
        Ok(self.memory()?.flows.get(id).cloned().unwrap_or_default())
    }
    pub fn inspections(&self, id: &str) -> Result<Vec<Value>> {
        Ok(self
            .memory()?
            .inspections
            .get(id)
            .cloned()
            .unwrap_or_default())
    }
}
impl Memory {
    fn prune(&mut self, now: DateTime<Utc>) {
        self.codes.retain(|_, value| value.expires > now);
        self.access.retain(|_, value| value.expires > now);
        self.refresh.retain(|_, value| value.expires > now);
        let expired = self
            .sessions
            .values()
            .filter(|value| value.authn.time + Duration::days(30) <= now)
            .map(|value| value.id.clone())
            .collect::<Vec<_>>();
        for id in expired {
            self.end_session(&id, "session expired");
        }
    }
    fn event(&mut self, id: &str, stage: &str, user: &str, detail: &str) {
        self.protocol_event(id, "oidc", stage, "ok", user, detail);
    }
    fn protocol_event(
        &mut self,
        id: &str,
        protocol: &str,
        stage: &str,
        outcome: &str,
        user: &str,
        detail: &str,
    ) {
        let events = self.flows.entry(id.into()).or_default();
        events.insert(
            0,
            json!({"Time":Utc::now(), "Protocol":protocol, "Stage":stage,
            "Outcome":outcome, "User":user, "Detail":detail}),
        );
        events.truncate(20);
        if let Some(revision) = &self.revision {
            revision.send_modify(|value| *value = value.wrapping_add(1));
        }
    }
    fn inspection(
        &mut self,
        grant: &Grant,
        user: &User,
        stage: &str,
        claims: &Value,
        token: &str,
    ) -> Result<()> {
        let entries = self
            .inspections
            .entry(grant.environment.clone())
            .or_default();
        let entry = json!({"Stage":stage, "ClientID":grant.client, "User":label(user),
            "RedirectURI":grant.redirect, "Scope":grant.scope, "PKCE":!grant.challenge.is_empty(),
            "Claims":if claims.is_null() { String::new() } else { serde_json::to_string_pretty(claims).map_err(Error::from)? },
            "IDToken":token, "Faults":grant.faults.describe(), "UpdatedAt":Utc::now()});
        if !token.is_empty()
            && let Some(previous) = entries.iter_mut().find(|value| {
                value["ClientID"] == grant.client
                    && value["User"] == label(user)
                    && value["IDToken"] == ""
            })
        {
            *previous = entry;
            return Ok(());
        }
        entries.insert(0, entry);
        entries.truncate(10);
        Ok(())
    }
}
pub fn random_secret(length: usize) -> String {
    let mut bytes = vec![0; length];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
fn param<'a>(values: &'a Parameters, name: &str) -> &'a str {
    values.get(name).map(String::as_str).unwrap_or_default()
}
fn has_scope(scope: &str, value: &str) -> bool {
    scope.split_whitespace().any(|word| word == value)
}
fn truthy(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}
fn label(user: &User) -> String {
    let name = format!("{} {}", user.fields.given_name, user.fields.family_name)
        .trim()
        .to_owned();
    if name.is_empty() {
        user.fields.username.clone()
    } else {
        name
    }
}
fn active_user<'a>(directory: &'a Directory, id: &str) -> Option<&'a User> {
    directory.users.iter().find(|user| {
        user.id == id
            && user.fields.active
            && !user.deleted
            && !directory.user_sync.get(id).is_some_and(|sync| sync.deleted)
    })
}
pub fn constant_equal(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

fn selected_user<'a>(directory: &'a Directory, values: &Parameters) -> Option<&'a User> {
    if directory.environment.settings.chooser_mode != "identifier" {
        return active_user(directory, param(values, "user_id"));
    }
    chooser::login_user(directory, param(values, "login_identifier"))
}
