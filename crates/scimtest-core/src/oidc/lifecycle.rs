use super::*;
use crate::{
    model::{Environment, Group, UserInput},
    scim,
};
use serde::{Deserialize, Serialize};

mod groups;
mod logout;
mod pushes;
mod start;
pub(super) use groups::IssuedGroups;

/// The execution status of a lifecycle run or checklist step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStatus {
    Running,
    Waiting,
    NeedsBrowser,
    Ok,
    Failed,
    Skipped,
}
impl LifecycleStatus {
    /// Returns the status name used in lifecycle messages and API responses.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Waiting => "waiting",
            Self::NeedsBrowser => "needs_browser",
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct JoinerInput {
    pub given_name: String,
    pub family_name: String,
    pub email: String,
    pub username: String,
    pub group_ids: Vec<String>,
}
#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MoverInput {
    pub user_id: String,
    pub add_group_ids: Vec<String>,
    pub remove_group_ids: Vec<String>,
}
#[derive(Clone, Serialize)]
pub struct LifecycleRun {
    pub id: String,
    pub kind: String,
    pub user_id: String,
    pub user: String,
    pub status: LifecycleStatus,
    pub started_at: String,
    pub steps: Vec<LifecycleStep>,
    #[serde(skip)]
    expected_groups: Vec<String>,
}
#[derive(Clone, Serialize)]
pub struct LifecycleStep {
    pub id: String,
    pub protocol: String,
    pub title: String,
    pub status: LifecycleStatus,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub detail: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<LifecycleMessage>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub browser_url: String,
    #[serde(skip)]
    session: Option<Session>,
    #[serde(skip)]
    request_id: String,
}
#[derive(Clone, Serialize)]
pub struct LifecycleMessage {
    pub at: String,
    pub sent: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub to: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub body: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub response: String,
    pub outcome: String,
}
impl LifecycleRun {
    fn new(kind: &str, user: &User) -> Self {
        Self {
            id: crate::store::new_id("lifecycle"),
            kind: kind.into(),
            user_id: user.id.clone(),
            user: label(user),
            status: LifecycleStatus::Running,
            started_at: timestamp(),
            steps: Vec::new(),
            expected_groups: Vec::new(),
        }
    }
    fn settle_status(&mut self) {
        self.status = if self
            .steps
            .iter()
            .any(|step| step.status == LifecycleStatus::Running)
        {
            LifecycleStatus::Running
        } else if self
            .steps
            .iter()
            .any(|step| step.status == LifecycleStatus::Failed)
        {
            LifecycleStatus::Failed
        } else if self.steps.iter().any(|step| {
            matches!(
                step.status,
                LifecycleStatus::Waiting | LifecycleStatus::NeedsBrowser
            )
        }) {
            LifecycleStatus::Waiting
        } else {
            LifecycleStatus::Ok
        };
    }
    pub fn with_browser_urls(mut self, base: &str, environment: &str) -> Self {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([("environment", environment), ("tab", "lifecycle")])
            .finish();
        for step in &mut self.steps {
            if step.status == LifecycleStatus::NeedsBrowser {
                step.browser_url = format!("{base}/?{query}#lifecycle-run-{}", self.id);
            }
        }
        self
    }
}
impl LifecycleStep {
    fn new(
        id: &str,
        protocol: &str,
        title: impl Into<String>,
        status: LifecycleStatus,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            protocol: protocol.into(),
            title: title.into(),
            status,
            detail: detail.into(),
            messages: Vec::new(),
            browser_url: String::new(),
            session: None,
            request_id: String::new(),
        }
    }
    pub fn can_send_logout(&self) -> bool {
        self.id.starts_with("saml-logout-") && self.status != LifecycleStatus::Ok
    }
}
fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

impl Identity {
    pub fn lifecycle_runs(&self, id: &str) -> Result<Vec<LifecycleRun>> {
        self.0.store.directory(id)?;
        let mut memory = self.memory()?;
        let mut runs = memory.lifecycle.remove(id).unwrap_or_default();
        for run in &mut runs {
            memory.settle_lifecycle(run, id);
        }
        memory.lifecycle.insert(id.into(), runs.clone());
        Ok(runs)
    }
    pub fn lifecycle_run(&self, id: &str, run_id: &str) -> Result<LifecycleRun> {
        self.lifecycle_runs(id)?
            .into_iter()
            .find(|run| run.id == run_id)
            .ok_or_else(|| ProtocolError {
                status: 404,
                ..ProtocolError::new("not_found", &format!("lifecycle run {run_id:?} not found"))
            })
    }
}
