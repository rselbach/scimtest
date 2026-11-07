use super::*;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    any::Any,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Status {
    #[default]
    Idle,
    Ready,
    Available,
    Failed,
    Restarting,
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub status: Status,
    pub current_version: String,
    pub version: String,
    pub notes_url: String,
    pub highlights: Vec<String>,
    pub download_url: String,
    pub failure: String,
}

#[derive(Clone)]
pub struct Install {
    pub version: String,
    pub build: u64,
    pub os_version: [u32; 3],
}

pub struct Platform {
    pub os: String,
    pub arch: String,
    pub kind: String,
}

pub trait Staged: Any + Send + Sync {
    fn build(&self) -> u64;
    fn as_any(&self) -> &dyn Any;
}

pub trait Installer: Send + Sync {
    fn replaceable(&self) -> bool;
    fn remove_leftovers(&self);
    fn stage(&self, archive: &Path, release: &Release) -> Result<Arc<dyn Staged>>;
    fn apply(&self, staged: &dyn Staged, relaunch: bool) -> Result<()>;
    fn discard(&self, staged: &dyn Staged);
}

pub struct Config {
    pub feed_url: String,
    pub public_key: String,
    pub current: Install,
    pub platform: Platform,
    pub state_dir: PathBuf,
    pub installer: Option<Arc<dyn Installer>>,
    pub client: reqwest::Client,
}

#[derive(Default, Deserialize, Serialize)]
struct Preferences {
    #[serde(default)]
    last_check: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    last_version: String,
}

struct State {
    snapshot: Snapshot,
    staged: Option<Arc<dyn Staged>>,
    restarting: bool,
    preferences: Preferences,
}

struct Inner {
    config: Config,
    state: Mutex<State>,
    operation: tokio::sync::Mutex<()>,
    changes: watch::Sender<Snapshot>,
    cancel: CancellationToken,
}

#[derive(Clone)]
pub struct Updater(Arc<Inner>);

impl Updater {
    pub fn new(config: Config) -> Result<Self> {
        let mut directory = std::fs::DirBuilder::new();
        directory.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directory.mode(0o700);
        }
        directory
            .create(&config.state_dir)
            .context("Create updater state")?;
        let path = config.state_dir.join("updater.json");
        let mut preferences = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|error| {
                eprintln!("Read updater preferences: {error}");
                Preferences::default()
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Preferences::default(),
            Err(error) => {
                eprintln!("Read updater preferences: {error}");
                Preferences::default()
            }
        };
        preferences.last_version = config.current.version.clone();
        let snapshot = Snapshot {
            current_version: config.current.version.clone(),
            ..Default::default()
        };
        let (changes, _) = watch::channel(snapshot.clone());
        let updater = Self(Arc::new(Inner {
            config,
            state: Mutex::new(State {
                snapshot,
                staged: None,
                restarting: false,
                preferences,
            }),
            operation: tokio::sync::Mutex::new(()),
            changes,
            cancel: CancellationToken::new(),
        }));
        updater.save_preferences();
        Ok(updater)
    }

    fn state(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        self.0
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("updater state lock is poisoned"))
    }

    pub fn snapshot(&self) -> Snapshot {
        self.0.changes.borrow().clone()
    }
    pub fn subscribe(&self) -> watch::Receiver<Snapshot> {
        self.0.changes.subscribe()
    }

    fn publish(&self, state: &State) {
        self.0.changes.send_replace(state.snapshot.clone());
    }

    pub async fn run(&self, cancel: CancellationToken) {
        if let Some(installer) = self.0.config.installer.clone()
            && let Err(error) =
                tokio::task::spawn_blocking(move || installer.remove_leftovers()).await
        {
            eprintln!("Clean earlier updates: {error}");
        }
        let mut next = Duration::from_secs(10);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(next) => {}
            }
            let due = self.state().map(|state| {
                state.preferences.last_check.is_none_or(|checked| {
                    chrono::Utc::now()
                        .signed_duration_since(checked)
                        .num_hours()
                        >= 24
                })
            });
            match due {
                Ok(true) => {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        result = self.check() => if let Err(error) = result { eprintln!("Check updates: {error:#}"); },
                    }
                }
                Ok(false) => {}
                Err(error) => eprintln!("Read update schedule: {error}"),
            }
            next = Duration::from_secs(3600);
        }
    }

    pub fn cancel(&self) {
        self.0.cancel.cancel();
    }

    pub async fn check(&self) -> Result<()> {
        tokio::select! {
            _ = self.0.cancel.cancelled() => anyhow::bail!("update check cancelled"),
            result = self.check_inner() => result,
        }
    }

    async fn check_inner(&self) -> Result<()> {
        let _operation = self.0.operation.lock().await;
        if self.state()?.restarting {
            return Ok(());
        }
        let config = &self.0.config;
        let release = read_feed(&config.client, &config.feed_url, &config.public_key).await?;
        self.state()?.preferences.last_check = Some(chrono::Utc::now());
        self.save_preferences();
        let kind = if config.installer.is_some() {
            "app-zip"
        } else {
            &config.platform.kind
        };
        let Some(artifact) = release.artifact(&config.platform.os, &config.platform.arch, kind)
        else {
            return self.up_to_date();
        };
        let newer = if config.installer.is_some() {
            release.build > config.current.build
                && parse_version(&artifact.minimum_os)
                    .is_some_and(|minimum| minimum <= config.current.os_version)
        } else {
            parse_version(&config.current.version)
                .zip(parse_version(&release.version))
                .is_some_and(|(current, offered)| current < offered)
        };
        if !newer {
            return self.up_to_date();
        }
        let manual = release
            .artifact(&config.platform.os, &config.platform.arch, "dmg")
            .unwrap_or(artifact)
            .url
            .clone();
        let Some(installer) = config
            .installer
            .clone()
            .filter(|installer| installer.replaceable())
        else {
            let mut state = self.state()?;
            if state.staged.is_none() {
                state.snapshot = offer(&config.current, &release, manual, Status::Available);
                self.publish(&state);
            }
            return Ok(());
        };
        if self
            .state()?
            .staged
            .as_ref()
            .is_some_and(|staged| staged.build() >= release.build)
        {
            return Ok(());
        }
        let path = match download(
            &config.client,
            artifact,
            &config.state_dir.join("downloads"),
        )
        .await
        {
            Ok(path) => path,
            Err(error) => {
                self.fail(&release, manual, "The update download could not be verified or did not finish. scimtest will try again at the next check.")?;
                return Err(error);
            }
        };
        let stage_release = release.clone();
        let stage_installer = installer.clone();
        let staged = tokio::task::spawn_blocking(move || {
            let result = stage_installer.stage(&path, &stage_release);
            if let Err(error) = std::fs::remove_file(path) {
                eprintln!("Remove update download: {error}");
            }
            result
        })
        .await
        .context("Join update staging")?;
        let staged = match staged {
            Ok(staged) => staged,
            Err(error) => {
                self.fail(&release, manual, "The update did not pass its signature checks, so scimtest deleted it. It will try again at the next check.")?;
                return Err(error);
            }
        };
        let previous = {
            let mut state = self.state()?;
            state.snapshot = offer(&config.current, &release, manual, Status::Ready);
            let previous = state.staged.replace(staged);
            self.publish(&state);
            previous
        };
        if let Some(previous) = previous {
            tokio::task::spawn_blocking(move || installer.discard(previous.as_ref()))
                .await
                .context("Discard previous update")?;
        }
        Ok(())
    }

    fn up_to_date(&self) -> Result<()> {
        let mut state = self.state()?;
        if state.staged.is_none() && !state.restarting {
            state.snapshot = Snapshot {
                current_version: self.0.config.current.version.clone(),
                ..Default::default()
            };
            self.publish(&state);
        }
        Ok(())
    }

    fn fail(&self, release: &Release, download: String, failure: &str) -> Result<()> {
        let mut state = self.state()?;
        if state.staged.is_none() {
            state.snapshot = offer(&self.0.config.current, release, download, Status::Failed);
            state.snapshot.failure = failure.into();
            self.publish(&state);
        }
        Ok(())
    }

    pub async fn apply(&self, relaunch: bool) -> Result<()> {
        let _operation = self.0.operation.lock().await;
        let installer = self
            .0
            .config
            .installer
            .clone()
            .context("This copy cannot replace itself")?;
        let staged = self.state()?.staged.clone().context("No update is ready")?;
        self.state()?.restarting = true;
        let apply_installer = installer.clone();
        let apply_staged = staged.clone();
        let result = tokio::task::spawn_blocking(move || {
            apply_installer.apply(apply_staged.as_ref(), relaunch)
        })
        .await
        .context("Join update installation")?;
        match result {
            Ok(()) => {
                let mut state = self.state()?;
                state.staged = None;
                state.snapshot.status = Status::Restarting;
                self.publish(&state);
                Ok(())
            }
            Err(error) => {
                let stranded = error.downcast_ref::<super::Stranded>().is_some();
                {
                    let mut state = self.state()?;
                    state.staged = None;
                    state.restarting = stranded;
                    state.snapshot.status = Status::Failed;
                    state.snapshot.failure = error.to_string();
                    self.publish(&state);
                }
                if !stranded {
                    tokio::task::spawn_blocking(move || installer.discard(staged.as_ref()))
                        .await
                        .context("Discard failed update")?;
                }
                Err(error)
            }
        }
    }

    fn save_preferences(&self) {
        let save = || -> Result<()> {
            use std::io::Write;
            let bytes = serde_json::to_vec(&self.state()?.preferences)?;
            let mut file = tempfile::NamedTempFile::new_in(&self.0.config.state_dir)?;
            file.write_all(&bytes)?;
            file.as_file().sync_all()?;
            file.persist(self.0.config.state_dir.join("updater.json"))?;
            Ok(())
        };
        if let Err(error) = save() {
            eprintln!("Save updater preferences: {error:#}");
        }
    }
}

fn offer(current: &Install, release: &Release, download_url: String, status: Status) -> Snapshot {
    Snapshot {
        status,
        current_version: current.version.clone(),
        version: release.version.clone(),
        notes_url: release.notes_url.clone(),
        highlights: release.highlights.clone(),
        download_url,
        failure: String::new(),
    }
}
