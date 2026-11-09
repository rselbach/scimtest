use super::*;
use crate::{Store, store::SyncLease};
use chrono::Utc;
use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
};
use tokio::task::JoinHandle;

#[derive(Clone, Default, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Job {
    pub id: String,
    pub environment_name: String,
    #[serde(flatten)]
    state: JobState,
    pub trace_available: bool,
    pub total: usize,
    pub processed: usize,
    pub percent: usize,
    pub message: String,
    pub current: String,
    pub started_at: String,
    pub latest_sequence: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<JobEvent>,
}
#[derive(Clone, Default, Debug)]
enum JobState {
    #[default]
    Running,
    RateLimited,
    Finished {
        outcome: std::result::Result<(), String>,
        at: String,
    },
}
impl Job {
    /// Reports whether the job is still processing or waiting to retry.
    pub fn is_running(&self) -> bool {
        matches!(self.state, JobState::Running | JobState::RateLimited)
    }
    /// Reports whether the job has finished.
    pub fn is_done(&self) -> bool {
        !self.is_running()
    }
    /// Reports whether the job finished successfully.
    pub fn is_success(&self) -> bool {
        matches!(
            self.state,
            JobState::Finished {
                outcome: Ok(()),
                ..
            }
        )
    }
    /// Reports whether the job is waiting after a rate limit response.
    pub fn is_rate_limited(&self) -> bool {
        matches!(self.state, JobState::RateLimited)
    }
    /// Returns the terminal failure, or an empty string when there is none.
    pub fn error(&self) -> &str {
        match &self.state {
            JobState::Finished {
                outcome: Err(error),
                ..
            } => error,
            _ => "",
        }
    }
}
impl Serialize for JobState {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct View<'a> {
            running: bool,
            done: bool,
            success: bool,
            rate_limited: bool,
            error: &'a str,
            #[serde(skip_serializing_if = "str::is_empty")]
            finished_at: &'a str,
        }
        let (done, success, error, finished_at) = match self {
            Self::Running | Self::RateLimited => (false, false, "", ""),
            Self::Finished {
                outcome: Ok(()),
                at,
            } => (true, true, "", at.as_str()),
            Self::Finished {
                outcome: Err(error),
                at,
            } => (true, false, error.as_str(), at.as_str()),
        };
        View {
            running: !done,
            done,
            success,
            rate_limited: matches!(self, Self::RateLimited),
            error,
            finished_at,
        }
        .serialize(serializer)
    }
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JobEvent {
    pub sequence: usize,
    pub id: String,
    pub resource_type: String,
    #[serde(rename = "resourceID")]
    pub resource_id: String,
    pub label: String,
    pub operation: String,
    pub phase: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub detail: String,
}
#[derive(Default)]
struct State {
    jobs: HashMap<String, Job>,
    cancellations: HashMap<String, Cancellation>,
    handles: Vec<JoinHandle<()>>,
    traces: HashMap<String, Vec<Trace>>,
    stopping: bool,
    previews: HashMap<String, super::import::Preview>,
}
struct Inner {
    store: Store,
    state: Mutex<State>,
    revision: tokio::sync::watch::Sender<u64>,
    handle: Option<tokio::runtime::Handle>,
}
#[derive(Clone)]
pub struct Service(Arc<Inner>);
impl Service {
    pub fn new(store: Store) -> Self {
        let (revision, _) = tokio::sync::watch::channel(0);
        Self(Arc::new(Inner {
            store,
            state: Mutex::new(State::default()),
            revision,
            handle: tokio::runtime::Handle::try_current().ok(),
        }))
    }
    fn state(&self) -> std::result::Result<MutexGuard<'_, State>, Error> {
        self.0.state.lock().map_err(|_| Error::Lock)
    }
    fn changed(&self) {
        self.0
            .revision
            .send_modify(|value| *value = value.wrapping_add(1));
    }
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.0.revision.subscribe()
    }
    pub fn status(&self, id: &str, after: usize) -> std::result::Result<Option<Job>, Error> {
        self.0.store.directory(id)?;
        let mut job = self.state()?.jobs.get(id).cloned();
        if after > 0
            && let Some(job) = &mut job
        {
            job.events.retain(|event| event.sequence > after);
        }
        Ok(job)
    }
    pub fn traces(&self, id: &str) -> std::result::Result<Vec<Trace>, Error> {
        self.0.store.directory(id)?;
        Ok(self.state()?.traces.get(id).cloned().unwrap_or_default())
    }
    pub fn start(&self, id: &str, mode: Mode) -> std::result::Result<Job, Error> {
        let handle = self
            .0
            .handle
            .clone()
            .or_else(|| tokio::runtime::Handle::try_current().ok())
            .ok_or_else(|| Error::Validation("SCIM jobs require an async runtime".into()))?;
        let mut state = self.state()?;
        if state.stopping {
            return Err(Error::Conflict("scimtest is shutting down".into()));
        }
        if let Some(active) = state.jobs.iter().find(|(_, job)| job.is_running()) {
            return Err(Error::Conflict(if active.0 == id {
                "sync already running".into()
            } else {
                format!(
                    "a sync is already running for {}; wait for it to finish",
                    active.1.environment_name
                )
            }));
        }
        let lease = self.0.store.begin_sync()?;
        let directory = self.0.store.directory(id)?;
        if !directory.environment.settings.scim_enabled {
            return Err(Error::Validation(
                "SCIM is not enabled for the active environment".into(),
            ));
        }
        if let Mode::Push {
            resource_type,
            resource_id,
        } = &mode
        {
            let exists = match resource_type.as_str() {
                "user" => directory.users.iter().any(|user| user.id == *resource_id),
                "group" => directory
                    .groups
                    .iter()
                    .any(|group| group.id == *resource_id),
                _ => false,
            };
            if !exists {
                return Err(Error::NotFound(if resource_type == "user" {
                    "user"
                } else {
                    "group"
                }));
            }
        }
        let kind = match &mode {
            Mode::Sync => "sync",
            Mode::Reconcile => "reconcile",
            Mode::Push { .. } => "push",
        };
        let job = Job {
            id: crate::store::new_id("sync"),
            environment_name: directory.environment.name.clone(),
            message: format!("Starting {kind} for {}", directory.environment.name),
            started_at: timestamp(),
            ..Default::default()
        };
        state.jobs.insert(id.into(), job.clone());
        let cancellation = Cancellation::default();
        state.cancellations.insert(id.into(), cancellation.clone());
        let service = self.clone();
        let id = id.to_owned();
        state.handles.retain(|handle| !handle.is_finished());
        state.handles.push(handle.spawn(async move {
            service.run(id, directory, mode, cancellation, lease).await;
        }));
        self.changed();
        Ok(job)
    }
    async fn run(
        &self,
        id: String,
        directory: Directory,
        mode: Mode,
        cancellation: Cancellation,
        lease: SyncLease,
    ) {
        let mut client = match Client::new(directory.environment.settings.clone(), cancellation) {
            Ok(client) => client,
            Err(error) => {
                drop(lease);
                self.finish(&id, false, &error.to_string(), Vec::new());
                return;
            }
        };
        let service = self.clone();
        let progress_id = id.clone();
        let callback: ProgressCallback =
            Arc::new(move |progress| service.progress(&progress_id, progress));
        let service = self.clone();
        let rate_id = id.clone();
        client.on_rate_limit = Some(Arc::new(move |target, delay, header, attempt| {
            service.rate_limit(&rate_id, target, delay, header, attempt)
        }));
        let result = client.sync(&directory, mode.clone(), Some(callback)).await;
        let success = result.success();
        let message = result.status(&mode);
        let traces = result.traces.clone();
        let store = self.0.store.clone();
        let saved_id = id.clone();
        let saved =
            tokio::task::spawn_blocking(move || store.save_sync_result(&saved_id, &result, &mode))
                .await;
        drop(lease);
        match saved {
            Ok(Ok(())) => self.finish(&id, success, &message, traces),
            Ok(Err(error)) => self.finish(&id, false, &error.to_string(), traces),
            Err(error) => self.finish(&id, false, &error.to_string(), traces),
        }
    }
    fn progress(&self, id: &str, progress: Progress) {
        let Ok(mut state) = self.state() else {
            return;
        };
        let Some(job) = state.jobs.get_mut(id) else {
            return;
        };
        if job.is_done() {
            return;
        }
        job.total = progress.total;
        job.processed = progress.processed;
        job.percent = percent(job.processed, job.total, false);
        if !progress.target.label.is_empty() {
            job.current = format!(
                "{} {} {}",
                progress.target.operation, progress.target.resource_type, progress.target.label
            )
            .trim()
            .into();
            if !progress.phase.is_empty() {
                job.latest_sequence += 1;
                job.events.push(JobEvent {
                    sequence: job.latest_sequence,
                    id: format!(
                        "{}:{}",
                        progress.target.resource_type, progress.target.resource_id
                    ),
                    resource_type: progress.target.resource_type,
                    resource_id: progress.target.resource_id,
                    label: progress.target.label,
                    operation: progress.target.operation,
                    phase: progress.phase,
                    detail: progress.detail,
                });
            }
        }
        job.state = if progress.rate_limited {
            JobState::RateLimited
        } else {
            JobState::Running
        };
        if !progress.status.is_empty() {
            job.message = progress.status;
        }
        self.changed();
    }
    fn rate_limit(
        &self,
        id: &str,
        target: &Target,
        delay: std::time::Duration,
        header: &str,
        attempt: usize,
    ) {
        let Ok(state) = self.state() else {
            return;
        };
        let Some(job) = state.jobs.get(id) else {
            return;
        };
        let (total, processed) = (job.total, job.processed);
        drop(state);
        self.progress(
            id,
            Progress {
                total,
                processed,
                target: target.clone(),
                phase: "waiting".into(),
                status: "Rate limited".into(),
                detail: format!(
                    "Retry {attempt} after {} seconds (Retry-After: {header})",
                    delay.as_secs_f64()
                ),
                rate_limited: true,
            },
        );
    }
    fn finish(&self, id: &str, success: bool, message: &str, traces: Vec<Trace>) {
        let Ok(mut state) = self.state() else {
            return;
        };
        let Some(job) = state.jobs.get_mut(id) else {
            return;
        };
        job.state = JobState::Finished {
            outcome: if success { Ok(()) } else { Err(message.into()) },
            at: timestamp(),
        };
        job.trace_available = !traces.is_empty();
        job.message = message.into();
        job.percent = percent(job.processed, job.total, true);
        state.traces.insert(id.into(), traces);
        state.cancellations.remove(id);
        self.changed();
    }
    pub fn cancel(&self, id: &str) -> std::result::Result<(), Error> {
        self.0.store.directory(id)?;
        let state = self.state()?;
        let cancellation = state
            .cancellations
            .get(id)
            .ok_or_else(|| Error::Conflict("no sync is running".into()))?;
        cancellation.cancel();
        Ok(())
    }
    pub(crate) fn cancel_all(&self) -> std::result::Result<(), Error> {
        let mut state = self.state()?;
        state.stopping = true;
        for cancellation in state.cancellations.values() {
            cancellation.cancel();
        }
        Ok(())
    }
    pub async fn shutdown(&self) -> std::result::Result<(), Error> {
        self.cancel_all()?;
        let handles = {
            let mut state = self.state()?;
            std::mem::take(&mut state.handles)
        };
        for handle in handles {
            handle
                .await
                .map_err(|error| Error::Io(std::io::Error::other(error)))?;
        }
        Ok(())
    }
    pub async fn preview_import(&self, id: String) -> std::result::Result<PreviewView, Error> {
        let store = self.0.store.clone();
        let load_id = id.clone();
        let (directory, digest) =
            tokio::task::spawn_blocking(move || super::import::baseline(&store, &load_id))
                .await
                .map_err(|error| Error::Io(std::io::Error::other(error)))??;
        let mut client = Client::new(
            directory.environment.settings.clone(),
            Cancellation::default(),
        )?;
        let result = client.import(&directory).await;
        self.state()?
            .traces
            .insert(id.clone(), client.traces.clone());
        self.changed();
        let (users, groups, skipped) =
            result.map_err(|error| Error::Validation(error.to_string()))?;
        let (added, updated, removed) = super::import::changes(&directory, &users, &groups);
        let mut status = format!(
            "imported {} users and {} groups from SCIM",
            users.len(),
            groups.len()
        );
        if skipped > 0 {
            status += &format!("; skipped {skipped} group members that are not imported users");
        }
        let view = PreviewView {
            added,
            updated,
            removed,
            digest,
            status,
            created_at: Utc::now(),
        };
        self.state()?.previews.insert(
            id,
            super::import::Preview {
                view: view.clone(),
                users,
                groups,
                traces: client.traces,
            },
        );
        self.changed();
        Ok(view)
    }
    pub fn import_preview(&self, id: &str) -> std::result::Result<PreviewView, Error> {
        let mut state = self.state()?;
        if state
            .previews
            .get(id)
            .is_some_and(|preview| preview.expired())
        {
            state.previews.remove(id);
        }
        state
            .previews
            .get(id)
            .map(|preview| preview.view.clone())
            .ok_or(Error::NotFound("import preview not found or expired"))
    }
    pub fn apply_import(&self, id: &str) -> std::result::Result<String, Error> {
        let mut state = self.state()?;
        let preview = state
            .previews
            .get(id)
            .filter(|preview| !preview.expired())
            .ok_or_else(|| {
                Error::Conflict("import preview expired; preview the directory again".into())
            })?;
        match self.0.store.apply_scim_import(id, preview) {
            Ok(()) => {
                let status = preview.view.status.clone();
                state.previews.remove(id);
                self.changed();
                Ok(status)
            }
            Err(error @ Error::Conflict(_)) => {
                state.previews.remove(id);
                Err(error)
            }
            Err(error) => Err(error),
        }
    }
    pub async fn discover(
        &self,
        id: String,
        save: bool,
    ) -> std::result::Result<(bool, bool), Error> {
        let store = self.0.store.clone();
        let load_id = id.clone();
        let directory = tokio::task::spawn_blocking(move || store.directory(&load_id))
            .await
            .map_err(|error| Error::Io(std::io::Error::other(error)))??;
        let mut client = Client::new(
            directory.environment.settings.clone(),
            Cancellation::default(),
        )?;
        let result = client.discover().await;
        self.state()?
            .traces
            .insert(id.clone(), client.traces.clone());
        self.changed();
        let (patch, filter) = result.map_err(|error| Error::Validation(error.to_string()))?;
        if save {
            let store = self.0.store.clone();
            tokio::task::spawn_blocking(move || {
                let fresh = store.directory(&id)?;
                if !fresh.environment.settings.scim_enabled
                    || fresh
                        .environment
                        .settings
                        .scim_base_url
                        .trim_end_matches('/')
                        != directory
                            .environment
                            .settings
                            .scim_base_url
                            .trim_end_matches('/')
                    || fresh.environment.settings.scim_bearer_token
                        != directory.environment.settings.scim_bearer_token
                {
                    return Err(Error::Conflict(
                        "SCIM configuration changed during discovery".into(),
                    ));
                }
                store.set_scim_capabilities(&id, patch, filter, &client.traces)
            })
            .await
            .map_err(|error| Error::Io(std::io::Error::other(error)))??;
        }
        Ok((patch, filter))
    }
}
fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
fn percent(processed: usize, total: usize, done: bool) -> usize {
    if done {
        return 100;
    }
    if total == 0 {
        return 0;
    }
    (processed.saturating_mul(100) / total).min(if done { 100 } else { 99 })
}
