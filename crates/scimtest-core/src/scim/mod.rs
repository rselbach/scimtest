mod entra;
mod import;
mod jobs;
pub use import::PreviewView;
mod persistence;
pub use jobs::{Job, JobEvent, Service};
mod sync;
pub use sync::{Mode, Progress, ProgressCallback, SyncResult};
mod resources;
mod transport;
mod validation;

use crate::{Error, configuration::EnvironmentSettings, model::Directory};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

pub use resources::{group_resource, user_resource};

pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const ENTERPRISE_SCHEMA: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
pub const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Trace {
    pub resource_type: String,
    #[serde(rename = "ResourceID")]
    pub resource_id: String,
    pub label: String,
    pub operation: String,
    pub method: String,
    pub path: String,
    pub request_body: String,
    pub status: String,
    pub response_retry_after: String,
    pub response_body: String,
    pub err: String,
    pub created_at: String,
}
#[derive(Clone, Default, Debug)]
pub struct Target {
    pub resource_type: String,
    pub resource_id: String,
    pub label: String,
    pub operation: String,
}
#[derive(Clone, Debug, thiserror::Error)]
#[error("{message}")]
pub struct Failure {
    pub message: String,
    pub status: u16,
    pub retry_after: String,
    pub cancelled: bool,
}
impl Failure {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: 0,
            retry_after: String::new(),
            cancelled: false,
        }
    }
    pub fn stops_sync(&self) -> bool {
        self.cancelled || self.status == 429
    }
    pub fn not_found(&self) -> bool {
        [404, 410].contains(&self.status)
    }
}
impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::new(error.to_string())
    }
}
impl From<reqwest::Error> for Failure {
    fn from(error: reqwest::Error) -> Self {
        Self::new(error.to_string())
    }
}
type Result<T> = std::result::Result<T, Failure>;

#[derive(Clone)]
pub struct Cancellation(Arc<tokio::sync::watch::Sender<bool>>);
impl Default for Cancellation {
    fn default() -> Self {
        let (sender, _) = tokio::sync::watch::channel(false);
        Self(Arc::new(sender))
    }
}
impl Cancellation {
    pub fn cancel(&self) {
        self.0.send_replace(true);
    }
    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }
    async fn wait(&self) {
        let mut receiver = self.0.subscribe();
        if let Err(error) = receiver.wait_for(|value| *value).await {
            eprintln!("Wait for SCIM cancellation: {error}");
        }
    }
}

type RateLimitCallback = Arc<dyn Fn(&Target, std::time::Duration, &str, usize) + Send + Sync>;
pub struct Client {
    settings: EnvironmentSettings,
    http: reqwest::Client,
    cancellation: Cancellation,
    pub traces: Vec<Trace>,
    pub on_rate_limit: Option<RateLimitCallback>,
}
impl Client {
    pub fn new(
        settings: EnvironmentSettings,
        cancellation: Cancellation,
    ) -> std::result::Result<Self, Error> {
        if !settings.scim_enabled {
            return Err(Error::Validation("SCIM is disabled".into()));
        }
        if settings.scim_base_url.is_empty() || settings.scim_bearer_token.is_empty() {
            return Err(Error::Validation(
                "SCIM base URL and bearer token are required".into(),
            ));
        }
        crate::configuration::validate_http_url("SCIM base URL", &settings.scim_base_url, true)?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .map_err(|error| Error::Validation(error.to_string()))?;
        Ok(Self {
            settings,
            http,
            cancellation,
            traces: Vec::new(),
            on_rate_limit: None,
        })
    }
    pub async fn discover(&mut self) -> Result<(bool, bool)> {
        let config = self
            .request(
                reqwest::Method::GET,
                "/ServiceProviderConfig",
                None,
                true,
                Target {
                    label: "SCIM ServiceProviderConfig".into(),
                    operation: "discover".into(),
                    ..Default::default()
                },
            )
            .await?;
        self.validate(validation::capabilities(&config))?;
        Ok((
            config["patch"]["supported"] == true,
            config["filter"]["supported"] == true,
        ))
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct PlanEntry {
    pub resource_type: String,
    pub resource_id: String,
    pub label: String,
    pub operation: String,
}
pub fn plan(directory: &Directory) -> Vec<PlanEntry> {
    let mut entries = Vec::new();
    for user in directory
        .projected_users()
        .into_iter()
        .filter(|user| user.dirty)
    {
        entries.push(PlanEntry {
            resource_type: "user".into(),
            resource_id: user.id.clone(),
            label: user_label(&user),
            operation: operation(user.deleted, &user.remote_id).into(),
        });
    }
    for group in directory
        .projected_groups()
        .into_iter()
        .filter(|group| group.dirty)
    {
        entries.push(PlanEntry {
            resource_type: "group".into(),
            resource_id: group.id,
            label: group.fields.display_name,
            operation: operation(group.deleted, &group.remote_id).into(),
        });
    }
    entries
}
fn operation(deleted: bool, remote: &str) -> &'static str {
    match (deleted, remote.is_empty()) {
        (true, true) => "forget",
        (true, false) => "delete",
        (false, true) => "create",
        _ => "update",
    }
}
fn user_label(user: &crate::model::User) -> String {
    let name = format!("{} {}", user.fields.given_name, user.fields.family_name)
        .trim()
        .to_owned();
    if name.is_empty() {
        user.fields.username.clone()
    } else {
        name
    }
}
fn resource_path(collection: &str, id: &str) -> String {
    format!(
        "{collection}/{}",
        url::form_urlencoded::byte_serialize(id.as_bytes())
            .collect::<String>()
            .replace('+', "%20")
    )
}
fn string<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name].as_str().unwrap_or_default().trim()
}
