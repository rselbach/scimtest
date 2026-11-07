mod icons;
mod information;
mod menus;
mod theme;
mod updates;
mod workspace;

use std::{
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

use anyhow::{Context, Result};
use rune::{App, AppHandle, AppSpec, WindowHandle, WindowOptions, WindowSpec};
use scimtest_core::{
    Store,
    model::EnvironmentInput,
    runtime::{Launch, Options, Runtime},
    update::{Status, Updater},
};
use workspace::{Lander, Services, Workspace};

/// The app's windows, for code that opens or updates them.
pub struct Shell {
    pub app: AppHandle<Workspace>,
    pub information: AppHandle<information::Information>,
    pub information_window: WindowHandle,
}

/// What the process stops when it ends: on macOS Quit the OS exits before `run` returns, so
/// the window's close hook finishes it; a quit from the app returns from `run` instead.
struct Lifetime {
    service: Option<Runtime>,
    updater: Option<Updater>,
    update_task: Option<tokio::task::JoinHandle<()>>,
    update_cancel: tokio_util::sync::CancellationToken,
    executor: tokio::runtime::Handle,
}

static LIFETIME: OnceLock<Mutex<Option<Lifetime>>> = OnceLock::new();

fn finish() {
    let Some(lifetime) = LIFETIME.get() else {
        return;
    };
    let Some(lifetime) = lifetime
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
    else {
        return;
    };
    lifetime.update_cancel.cancel();
    if let Some(updater) = &lifetime.updater {
        updater.cancel();
    }
    if let Some(task) = lifetime.update_task
        && let Err(error) = lifetime.executor.block_on(task)
    {
        eprintln!("Join update worker: {error}");
    }
    if let Some(service) = lifetime.service
        && let Err(error) = lifetime.executor.block_on(service.shutdown())
    {
        eprintln!("Shutdown scimtest: {error:#}");
    }
    if let Some(updater) = lifetime.updater
        && updater.snapshot().status == Status::Ready
        && let Err(error) = lifetime.executor.block_on(updater.apply(false))
    {
        eprintln!("Install update on quit: {error:#}");
    }
}

fn spec() -> AppSpec<Workspace> {
    AppSpec {
        min_size: Some((960.0, 640.0)),
        setup: Some(|s, waker| s.setup(waker)),
        on_key: Some(menus::on_key),
        scenes: workspace::SCENES,
        ..AppSpec::new(
            "scimtest",
            (1280.0, 788.0),
            || unreachable!("the app supplies its first state"),
            workspace::view,
        )
    }
}

/// Builds the app around `services`, with its windows and menus.
fn app(
    services: impl FnOnce(Lander, Shell) -> Services + 'static,
    argv: Option<Vec<String>>,
) -> (App<Workspace>, AppHandle<Workspace>) {
    let buttons = (workspace::view::TOOLBAR_HEIGHT - rune::Chrome::TRAFFIC_LIGHT) / 2.0;
    let mut app = App::new(spec())
        .chrome(rune::Chrome {
            full_size_content: true,
            traffic_lights: Some((buttons + 4.0, buttons)),
            drag_regions: true,
        })
        .standard_menus()
        .on_close(|_, _| finish());
    if let Some(argv) = argv {
        app = app.args(argv);
    }
    let handle = app.handle();
    let (information, information_window) = app.window(
        WindowSpec::new(
            "information",
            AppSpec {
                min_size: Some((400.0, 280.0)),
                on_key: Some(information::on_key),
                ..AppSpec::new(
                    "scimtest",
                    (620.0, 480.0),
                    information::Information::default,
                    information::view,
                )
            },
        )
        .chrome(rune::Chrome {
            full_size_content: false,
            ..rune::Chrome::DEFAULT
        })
        .options(WindowOptions {
            visible: false,
            ..Default::default()
        }),
    );
    let shell = Shell {
        app: handle.clone(),
        information,
        information_window,
    };
    let landing = handle.clone();
    let lander = Lander::new(move |update| landing.update_if(update));
    let app = app.init(move || {
        let workspace = Workspace::new(services(lander, shell));
        workspace.watch_updates();
        workspace
    });
    (app, handle)
}

fn main() -> Result<()> {
    rune::set_app_id("scimtest-desktop");
    let executor = tokio::runtime::Runtime::new()?;
    if let Some(state) = std::env::var_os("SCIMTEST_PREVIEW_STATE") {
        return preview(executor, PathBuf::from(state));
    }
    let options = Options::parse_cli();
    let no_open = options.no_open;
    let service = match executor.block_on(Runtime::launch_desktop(options, executor.handle()))? {
        Launch::Started(service) => *service,
        Launch::Existing(instance) => {
            if !no_open {
                executor.block_on(instance.open())?;
            }
            return Ok(());
        }
    };
    let mut activations = service.subscribe_activation();
    let store = service.store.clone();
    let identity = service.identity.clone();
    let scim = service.scim.clone();
    let tunnel = service.tunnel.clone();
    let url = service.url.clone();
    let state_file = service.state_file.clone();
    let updater = match updates::new(&state_file) {
        Ok(updater) => Some(updater),
        Err(error) => {
            eprintln!("Updates unavailable: {error}");
            None
        }
    };
    let update_cancel = tokio_util::sync::CancellationToken::new();
    let update_task = updater.clone().map(|updater| {
        let cancel = update_cancel.clone();
        executor.spawn(async move { updater.run(cancel).await })
    });
    eprintln!("scimtest Rust API: {url}");
    eprintln!("Preview state: {}", state_file.display());
    if LIFETIME
        .set(Mutex::new(Some(Lifetime {
            service: Some(service),
            updater: updater.clone(),
            update_task,
            update_cancel,
            executor: executor.handle().clone(),
        })))
        .is_err()
    {
        anyhow::bail!("scimtest started twice");
    }
    let handle = executor.handle().clone();
    let update_label = updater
        .is_some()
        .then(|| updates::Controller::new(updater.clone(), store.clone()).menu_label());
    let (mut app, shell) = app(
        move |lander, shell| Services {
            updates: updates::Controller::new(updater, store.clone()),
            store,
            identity,
            scim,
            tunnel,
            executor: handle,
            api_url: url,
            lander,
            shell: Some(shell),
        },
        Some(Vec::new()),
    );
    for item in menus::items(update_label) {
        app = app.menu_item(item);
    }
    let termination = shell.clone();
    executor.spawn(async move {
        match scimtest_core::runtime::wait_for_termination().await {
            Ok(()) => termination.quit(),
            Err(error) => eprintln!("Listen for termination: {error}"),
        }
    });
    let activation = shell.clone();
    executor.spawn(async move {
        while activations.changed().await.is_ok() {
            activation.open();
        }
    });
    if let Some(marker) = information::release_notes_due(&state_file) {
        let notes = shell.clone();
        executor.spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(750)).await;
            notes.update(move |s, _| {
                let (title, body) = information::release_notes();
                information::show_message(s.shell.as_ref(), title, body);
                if let Err(error) =
                    information::remember_version(marker, scimtest_core::runtime::version())
                {
                    eprintln!("Remember release notes version: {error}");
                }
            });
        });
    }
    app.try_run()
        .map_err(anyhow::Error::msg)
        .context("Run scimtest")?;
    finish();
    Ok(())
}

/// Runs the workspace on the state file at `state`, without the server, so Rune's headless
/// flags (`--snap`, `--tree`, `--script`) can drive it. An empty file gets the Greendale sample.
fn preview(executor: tokio::runtime::Runtime, state: PathBuf) -> Result<()> {
    let store = Store::open(&state).with_context(|| format!("Open {}", state.display()))?;
    if store.snapshot()?.is_empty() {
        let environment = store.create_environment(EnvironmentInput {
            name: "Greendale Community College".into(),
            slug: "greendale".into(),
            ..Default::default()
        })?;
        store.seed_sample(&environment.id)?;
    }
    let identity = scimtest_core::oidc::Identity::new(store.clone());
    let scim = scimtest_core::scim::Service::new(store.clone());
    let tunnel = {
        let _entered = executor.enter();
        scimtest_core::tunnel::Service::new(store.clone(), None, 1)?
    };
    let handle = executor.handle().clone();
    let (app, _) = app(
        move |lander, shell| Services {
            updates: updates::Controller::new(None, store.clone()),
            store,
            identity,
            scim,
            tunnel,
            executor: handle,
            api_url: "http://127.0.0.1:8080".into(),
            lander,
            shell: Some(shell),
        },
        None,
    );
    app.try_run().map_err(anyhow::Error::msg)
}
