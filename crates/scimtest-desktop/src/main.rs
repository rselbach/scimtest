mod assets;
mod dropdown;
mod information;
mod menus;
mod theme;
mod updates;
mod workspace;

use std::{cell::RefCell, rc::Rc};

use anyhow::{Context, Result};
use gpui::{App, AppContext, Bounds, WindowBounds, WindowOptions, px, size};
use gpui_component::Root;
use scimtest_core::runtime::{Launch, Options, Runtime};

fn main() -> Result<()> {
    let executor = tokio::runtime::Runtime::new()?;
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
    let snapshot = service.store.snapshot()?;
    let store = service.store.clone();
    let identity = service.identity.clone();
    let scim_service = service.scim.clone();
    let tunnel_service = service.tunnel.clone();
    let handle = executor.handle().clone();
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
    let native_updater = updater.clone();
    eprintln!("scimtest Rust API: {url}");
    eprintln!("Preview state: {}", service.state_file.display());
    let service = Rc::new(RefCell::new(Some(service)));
    let quitting_service = service.clone();
    let stopped = Rc::new(RefCell::new(None));
    let quitting_task = stopped.clone();
    let quitting_executor = executor.handle().clone();
    let termination = executor.spawn(scimtest_core::runtime::wait_for_termination());
    let application = gpui_platform::application().with_assets(assets::Assets);
    application.on_reopen(|cx| cx.activate(true));
    application.run(move |cx: &mut App| {
        gpui_component::init(cx);
        theme::apply(cx);
        cx.spawn(async move |cx| match termination.await {
            Ok(Ok(())) => cx.update(|cx| cx.quit()),
            Ok(Err(error)) => eprintln!("Listen for termination: {error}"),
            Err(error) => eprintln!("Join termination listener: {error}"),
        })
        .detach();
        cx.spawn(async move |cx| {
            while activations.changed().await.is_ok() {
                cx.update(|cx| cx.activate(true));
            }
        })
        .detach();
        cx.on_app_quit(move |_| {
            if let Some(service) = quitting_service.borrow_mut().take() {
                *quitting_task.borrow_mut() = Some(quitting_executor.spawn(service.shutdown()));
            }
            async {}
        })
        .detach();
        let updates = cx
            .new(|cx| updates::Controller::new(native_updater, handle.clone(), store.clone(), cx));
        menus::install(updates.clone(), cx);
        cx.on_window_closed(|cx, _| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();
        let bounds = Bounds::centered(None, size(px(1280.), px(788.)), cx);
        if let Err(error) = cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_min_size: Some(size(px(960.), px(640.))),
                titlebar: Some(gpui::TitlebarOptions {
                    title: Some("scimtest · Rust preview".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            move |window, cx| {
                let view = cx.new(|cx| {
                    workspace::Workspace::new(
                        store,
                        identity,
                        scim_service,
                        tunnel_service,
                        handle,
                        snapshot,
                        url,
                        updates,
                        window,
                        cx,
                    )
                });
                workspace::Workspace::install_shortcuts(&view, window.window_handle(), cx);
                cx.new(|cx| Root::new(view, window, cx))
            },
        ) {
            eprintln!("Open scimtest window: {error}");
            cx.quit();
        }
        cx.activate(true);
        information::show_after_update(&state_file, cx);
    });
    update_cancel.cancel();
    if let Some(updater) = &updater {
        updater.cancel();
    }
    if let Some(task) = update_task {
        executor.block_on(task).context("Join update worker")?;
    }
    if let Some(task) = stopped.borrow_mut().take() {
        executor
            .block_on(task)
            .context("Join scimtest shutdown")??;
    } else if let Some(service) = service.borrow_mut().take() {
        executor.block_on(service.shutdown())?;
    }
    if let Some(updater) = updater
        && updater.snapshot().status == scimtest_core::update::Status::Ready
        && let Err(error) = executor.block_on(updater.apply(false))
    {
        eprintln!("Install update on quit: {error:#}");
    }
    Ok(())
}
