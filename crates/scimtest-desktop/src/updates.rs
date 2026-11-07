use anyhow::{Context as _, Result, ensure};
use rune::{El, Tx};
use rune_kit::{Button, ButtonVariant};
use scimtest_core::{
    Store,
    update::{self, Config, Snapshot, Status, Updater},
};
use std::path::Path;

use crate::{theme::Ui, workspace::Workspace};

pub fn new(state_file: &Path) -> Result<Updater> {
    #[cfg(target_os = "macos")]
    let (current, installer, platform) = {
        let (current, installer) = update::MacInstaller::running()?;
        (
            current,
            Some(std::sync::Arc::new(installer) as std::sync::Arc<dyn update::Installer>),
            update::Platform {
                os: "macos".into(),
                arch: "arm64".into(),
                kind: "dmg".into(),
            },
        )
    };
    #[cfg(not(target_os = "macos"))]
    let (current, installer, platform) = {
        let version = option_env!("SCIMTEST_VERSION").unwrap_or("0.0.0");
        let kind = option_env!("SCIMTEST_PACKAGE_KIND").unwrap_or("");
        ensure!(
            matches!(kind, "deb" | "rpm" | "pkg.tar.zst"),
            "this build has no Linux package kind"
        );
        (
            update::Install {
                version: version.into(),
                build: 0,
                os_version: [0; 3],
            },
            None,
            update::Platform {
                os: std::env::consts::OS.into(),
                arch: if cfg!(target_arch = "aarch64") {
                    "arm64"
                } else {
                    "x86_64"
                }
                .into(),
                kind: kind.into(),
            },
        )
    };
    ensure!(
        update::parse_version(&current.version).is_some()
            && !matches!(current.version.as_str(), "0" | "0.0" | "0.0.0"),
        "development preview builds do not update"
    );
    Updater::new(Config {
        feed_url: update::FEED_URL.into(),
        public_key: update::PUBLIC_KEY.into(),
        current,
        platform,
        state_dir: state_file
            .parent()
            .context("Find state directory")?
            .join("updates"),
        installer,
        client: update::http_client()?,
    })
}

pub struct Controller {
    updater: Option<Updater>,
    snapshot: Snapshot,
    busy: bool,
    store: Store,
}

impl Controller {
    pub fn new(updater: Option<Updater>, store: Store) -> Self {
        Self {
            snapshot: updater.as_ref().map(Updater::snapshot).unwrap_or_default(),
            updater,
            busy: false,
            store,
        }
    }

    pub fn available(&self) -> bool {
        self.updater.is_some()
    }

    pub fn menu_label(&self) -> String {
        if self.busy {
            return "Checking for Updates…".into();
        }
        match self.snapshot.status {
            Status::Ready => format!("Restart to Update to {}…", self.snapshot.version),
            Status::Restarting => "Restarting…".into(),
            _ => "Check for Updates…".into(),
        }
    }

    pub fn button(&self, ui: &Ui) -> El {
        let label = match self.snapshot.status {
            Status::Ready => "Update ready",
            Status::Available => "Update available",
            Status::Failed => "Update failed",
            Status::Restarting => "Restarting…",
            Status::Idle => "Check for updates",
        };
        Button::new(label)
            .variant(ButtonVariant::Ghost)
            .on_press_tx(|s: &mut Workspace, tx: &mut Tx| {
                if s.updates.snapshot.status == Status::Available {
                    if let Err(error) = tx.open_url(&s.updates.snapshot.download_url) {
                        eprintln!("Open update download: {error}");
                    }
                } else {
                    s.update_action();
                }
            })
            .build(&ui.k)
            .key("desktop-update")
    }
}

impl Workspace {
    /// Follows the updater's state so the toolbar and menu reflect it.
    pub(crate) fn watch_updates(&self) {
        let Some(updater) = &self.updates.updater else {
            return;
        };
        let mut changes = updater.subscribe();
        let lander = self.lander.clone();
        self.spawn_future(async move {
            while changes.changed().await.is_ok() {
                let snapshot = changes.borrow_and_update().clone();
                lander.send(move |view, _| {
                    view.updates.snapshot = snapshot;
                    view.refresh_menus();
                    true
                });
            }
        });
    }

    /// Checks for an update, or restarts into one that is ready.
    pub(crate) fn update_action(&mut self) {
        let controller = &mut self.updates;
        if controller.busy || controller.snapshot.status == Status::Restarting {
            return;
        }
        let Some(updater) = controller.updater.clone() else {
            return;
        };
        let restart = controller.snapshot.status == Status::Ready;
        if restart && let Err(error) = controller.store.check_idle() {
            crate::information::show_message(
                self.shell.as_ref(),
                "Wait before restarting".into(),
                error.to_string(),
            );
            return;
        }
        controller.busy = true;
        self.refresh_menus();
        self.task(
            async move {
                let result = if restart {
                    updater.apply(true).await
                } else {
                    updater.check().await
                };
                (result, updater.snapshot())
            },
            move |view, (result, snapshot), tx| {
                view.updates.busy = false;
                view.updates.snapshot = snapshot;
                if restart && result.is_ok() {
                    tx.quit();
                    return;
                }
                let snapshot = &view.updates.snapshot;
                let (title, message) = match result {
                    Err(error) => ("scimtest could not update".into(), format!("{error:#}")),
                    Ok(()) => match snapshot.status {
                        Status::Ready => (
                            format!("scimtest {} is ready", snapshot.version),
                            "Choose Restart to Update in the scimtest menu or toolbar to finish updating.".into(),
                        ),
                        Status::Available => (
                            format!("scimtest {} is available", snapshot.version),
                            format!(
                                "[Download the new version]({}) and install it with your usual installer.",
                                snapshot.download_url
                            ),
                        ),
                        _ => (
                            "You’re up to date".into(),
                            format!("scimtest {} is the newest version.", snapshot.current_version),
                        ),
                    },
                };
                crate::information::show_message(view.shell.as_ref(), title, message);
                view.refresh_menus();
            },
        );
    }
}
