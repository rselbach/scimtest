use super::*;
use futures_util::{SinkExt, StreamExt};
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::{Message, protocol::CloseFrame};

struct Peer {
    disconnect: tokio::sync::mpsc::UnboundedSender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Peer {
    fn start(listener: std::net::TcpListener, executor: &tokio::runtime::Runtime) -> Self {
        listener.set_nonblocking(true).unwrap();
        let (disconnect, mut commands) = tokio::sync::mpsc::unbounded_channel();
        let task = executor.spawn(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let registration = socket.next().await.unwrap().unwrap();
                let registration: serde_json::Value =
                    serde_json::from_str(registration.to_text().unwrap()).unwrap();
                assert_eq!(registration["type"], "register_tunnel");
                socket
                    .send(Message::Text(
                        serde_json::json!({
                            "type": "application_challenge", "enrollment_supported": true,
                            "challenge": "greendale-recovery"
                        })
                        .to_string()
                        .into(),
                    ))
                    .await
                    .unwrap();
                let signature = socket.next().await.unwrap().unwrap();
                let signature: serde_json::Value =
                    serde_json::from_str(signature.to_text().unwrap()).unwrap();
                assert_eq!(signature["type"], "application_signature");
                socket
                    .send(Message::Text(
                        serde_json::json!({
                            "type": "tunnel_registered", "tunnel_id": "greendale-tunnel",
                            "public_url": "https://scimtest.example/greendale",
                            "github_user_id": 42, "github_login": "troy-barnes"
                        })
                        .to_string()
                        .into(),
                    ))
                    .await
                    .unwrap();
                tokio::select! {
                    command = commands.recv() => {
                        if command.is_none() {
                            return;
                        }
                        socket.send(Message::Close(Some(CloseFrame {
                            code: 1008.into(), reason: "Greendale recovery check".into(),
                        }))).await.unwrap();
                    }
                    _ = socket.next() => {}
                }
            }
        });
        Self { disconnect, task }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn wait(
    cx: &mut VisualTestContext,
    view: &Entity<Workspace>,
    predicate: impl Fn(&Workspace) -> bool,
) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        cx.executor().run_until_parked();
        let ready = cx.update(|window, cx| {
            window.draw(cx).clear(cx);
            predicate(view.read(cx))
        });
        if ready {
            return;
        }
        assert!(Instant::now() < deadline, "account transition timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn connected_fixture(
    cx: &mut TestAppContext,
) -> (
    Entity<Workspace>,
    &mut VisualTestContext,
    tempfile::TempDir,
    tokio::runtime::Runtime,
    Peer,
) {
    cx.executor().allow_parking();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let config = scimtest_core::tunnel::Config {
        server_base_url: format!("http://{}", listener.local_addr().unwrap()),
        application_profile_id: "0123456789abcdef0123456789abcdef".into(),
        require_account: true,
    };
    let (view, cx, temporary, executor) = fixture_with_tunnel(cx, Some(config));
    let peer = Peer::start(listener, &executor);
    cx.update(|_, cx| view.read(cx).tunnel_service.start().unwrap());
    wait(cx, &view, |view| view.tunnel_snapshot.connected);
    (view, cx, temporary, executor, peer)
}

fn retry(cx: &mut VisualTestContext, view: &Entity<Workspace>) {
    cx.update(|window, cx| {
        let workspace = view.read(cx);
        assert!(workspace.account_locked());
        assert!(workspace.account_focus.contains_focused(window, cx));
        let focus = workspace.account_focus.clone();
        window.focus(&focus, cx);
    });
    cx.simulate_keystrokes("tab");
    press_space(cx);
    wait(cx, view, |view| view.tunnel_snapshot.connected);
    cx.update(|window, cx| {
        window.simulate_next_frame(cx);
        window.draw(cx).clear(cx);
    });
}

#[gpui::test]
fn required_account_recovery_restores_keyboard_navigation(cx: &mut TestAppContext) {
    let (view, cx, _temporary, executor, peer) = connected_fixture(cx);
    cx.update(|window, cx| {
        let focus = view.read(cx).focus.clone();
        window.focus(&focus, cx);
    });
    cx.simulate_keystrokes("tab tab tab tab tab tab");
    press_space(cx);
    cx.update(|_, cx| assert!(view.read(cx).tab == Tab::Groups));
    let old_focus = cx.update(|window, cx| window.focused(cx).unwrap());
    peer.disconnect.send(()).unwrap();
    wait(cx, &view, |view| view.tunnel_snapshot.retry_available);
    cx.simulate_keystrokes("escape");
    retry(cx, &view);
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        let workspace = view.read(cx);
        assert!(!workspace.account_locked());
        assert!(
            workspace.focus.contains_focused(window, cx),
            "recovery left focus on an unmounted workspace control"
        );
        assert!(!old_focus.is_focused(window));
    });
    cx.update(|_, cx| view.update(cx, |view, _| view.tab = Tab::Users));
    cx.simulate_keystrokes("tab tab tab tab tab tab");
    press_space(cx);
    cx.update(|_, cx| assert!(view.read(cx).tab == Tab::Groups));
    let tunnel = cx.update(|_, cx| view.read(cx).tunnel_service.clone());
    executor.block_on(tunnel.shutdown()).unwrap();
}

#[gpui::test]
fn required_account_recovery_closes_the_editor_and_restores_search(cx: &mut TestAppContext) {
    let (view, cx, _temporary, executor, peer) = connected_fixture(cx);
    cx.update(|window, cx| {
        let focus = view.read(cx).search.focus_handle(cx);
        window.focus(&focus, cx);
        window.draw(cx).clear(cx);
        view.update(cx, |view, cx| view.edit_user(None, window, cx));
        window.draw(cx).clear(cx);
    });
    cx.simulate_input("troy.interrupted");
    peer.disconnect.send(()).unwrap();
    wait(cx, &view, |view| view.tunnel_snapshot.retry_available);
    cx.update(|_, cx| assert!(view.read(cx).editor.is_none()));
    cx.simulate_keystrokes("escape");
    retry(cx, &view);
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        assert!(view.read(cx).search.focus_handle(cx).is_focused(window));
        assert!(view.read(cx).editor.is_none());
    });
    cx.simulate_input("Troy");
    cx.update(|_, cx| {
        let workspace = view.read(cx);
        assert_eq!(workspace.search.read(cx).value().as_str(), "Troy");
        assert!(
            !workspace
                .directory()
                .unwrap()
                .users
                .iter()
                .any(|user| { user.fields.username == "troy.interrupted" })
        );
    });
    let tunnel = cx.update(|_, cx| view.read(cx).tunnel_service.clone());
    executor.block_on(tunnel.shutdown()).unwrap();
}

#[gpui::test]
fn account_connection_changes_keep_keyboard_focus_in_the_account_screen(cx: &mut TestAppContext) {
    let (view, cx, _temporary, executor, peer) = connected_fixture(cx);
    cx.update(|window, cx| {
        window.simulate_next_frame(cx);
        let focus = view.read(cx).focus.clone();
        window.focus(&focus, cx);
    });
    cx.simulate_keystrokes("tab tab tab");
    press_space(cx);
    cx.simulate_keystrokes("tab");
    cx.update(|window, cx| {
        let workspace = view.read(cx);
        assert!(workspace.account_open);
        assert!(workspace.account_focus.contains_focused(window, cx));
        assert!(!workspace.account_focus.is_focused(window));
    });
    peer.disconnect.send(()).unwrap();
    wait(cx, &view, |view| view.tunnel_snapshot.retry_available);
    cx.update(|window, cx| {
        window.simulate_next_frame(cx);
        window.draw(cx).clear(cx);
        assert!(view.read(cx).account_focus.contains_focused(window, cx));
    });
    retry(cx, &view);
    cx.update(|window, cx| {
        assert!(view.read(cx).account_open);
        assert!(view.read(cx).account_focus.contains_focused(window, cx));
    });
    cx.simulate_keystrokes("tab tab");
    press_space(cx);
    cx.update(|_, cx| assert!(!view.read(cx).account_open));
    press_space(cx);
    cx.update(|_, cx| assert!(view.read(cx).account_open));
    let tunnel = cx.update(|_, cx| view.read(cx).tunnel_service.clone());
    executor.block_on(tunnel.shutdown()).unwrap();
}
