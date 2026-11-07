use anyhow::{Context as _, Result, ensure};
use gpui::{App, Context, Entity};
use gpui_component::button::{Button, ButtonVariants};
use scimtest_core::{
    Store,
    update::{self, Config, Snapshot, Status, Updater},
};
use std::path::Path;

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
    executor: tokio::runtime::Handle,
    store: Store,
}

impl Controller {
    pub fn new(
        updater: Option<Updater>,
        executor: tokio::runtime::Handle,
        store: Store,
        cx: &mut Context<Self>,
    ) -> Self {
        if let Some(updater) = &updater {
            let mut changes = updater.subscribe();
            cx.spawn(async move |view, cx| {
                while changes.changed().await.is_ok() {
                    let snapshot = changes.borrow_and_update().clone();
                    if view
                        .update(cx, |view, cx| {
                            view.snapshot = snapshot;
                            crate::menus::refresh(cx, &view.menu_label());
                            cx.notify();
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            })
            .detach();
        }
        Self {
            snapshot: updater.as_ref().map(Updater::snapshot).unwrap_or_default(),
            updater,
            busy: false,
            executor,
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

    pub fn action(&mut self, cx: &mut Context<Self>) {
        if self.busy || self.snapshot.status == Status::Restarting {
            return;
        }
        let Some(updater) = self.updater.clone() else {
            return;
        };
        let restart = self.snapshot.status == Status::Ready;
        if restart && let Err(error) = self.store.check_idle() {
            crate::information::show_message(
                "Wait before restarting".into(),
                error.to_string(),
                cx,
            );
            return;
        }
        self.busy = true;
        crate::menus::refresh(cx, &self.menu_label());
        let task = self.executor.spawn(async move {
            let result = if restart {
                updater.apply(true).await
            } else {
                updater.check().await
            };
            (result, updater.snapshot())
        });
        cx.spawn(async move |view,cx| {
            let outcome = task.await;
            let _ = view.update(cx, |view,cx| {
                view.busy = false;
                match outcome {
                    Ok((Ok(()), snapshot)) if restart => { view.snapshot = snapshot; cx.quit(); return; }
                    Ok((result,snapshot)) => {
                        view.snapshot = snapshot;
                        let (title,message) = match result {
                            Err(error) => ("scimtest could not update".into(),format!("{error:#}")),
                            Ok(()) => match view.snapshot.status {
                                Status::Ready => (format!("scimtest {} is ready",view.snapshot.version),"Choose Restart to Update in the scimtest menu or toolbar to finish updating.".into()),
                                Status::Available => (format!("scimtest {} is available",view.snapshot.version),format!("[Download the new version]({}) and install it with your usual installer.",view.snapshot.download_url)),
                                _ => ("You’re up to date".into(),format!("scimtest {} is the newest version.",view.snapshot.current_version)),
                            },
                        };
                        crate::information::show_message(title,message,cx);
                    }
                    Err(error) => crate::information::show_message("scimtest could not update".into(),error.to_string(),cx),
                }
                crate::menus::refresh(cx,&view.menu_label());
                cx.notify();
            });
        }).detach();
        cx.notify();
    }
}

pub fn button(controller: &Entity<Controller>, cx: &App) -> Button {
    let state = controller.read(cx);
    let label = match state.snapshot.status {
        Status::Ready => "Update ready",
        Status::Available => "Update available",
        Status::Failed => "Update failed",
        Status::Restarting => "Restarting…",
        Status::Idle => "Check for updates",
    };
    let controller = controller.clone();
    Button::new("desktop-update")
        .label(label)
        .ghost()
        .on_click(move |_, _, cx| {
            let url = controller.read(cx).snapshot.download_url.clone();
            if controller.read(cx).snapshot.status == Status::Available {
                cx.open_url(&url);
            } else {
                controller.update(cx, |view, cx| view.action(cx));
            }
        })
}
