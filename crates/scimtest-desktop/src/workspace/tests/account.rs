use futures_util::{SinkExt, StreamExt};
use rune::Key;
use tokio_tungstenite::tungstenite::{Message, protocol::CloseFrame};

use super::Fixture;
use crate::workspace::{Editor, connection::Export};

/// A fake scimtest account server that registers Troy Barnes's tunnel on every connection
/// and drops the current one on request.
struct Peer {
    disconnect: tokio::sync::mpsc::UnboundedSender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Peer {
    fn start(listener: std::net::TcpListener, executor: &tokio::runtime::Handle) -> Self {
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

/// A workspace that requires an account, connected to a fake account server.
fn connected_fixture() -> (Fixture, Peer) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let config = scimtest_core::tunnel::Config {
        server_base_url: format!("http://{}", listener.local_addr().unwrap()),
        application_profile_id: "0123456789abcdef0123456789abcdef".into(),
        require_account: true,
    };
    let mut fixture = Fixture::with_tunnel(Some(config));
    let peer = Peer::start(listener, &fixture.state().executor);
    fixture.state().tunnel_service.start().unwrap();
    fixture.wait("the tunnel to connect", |state| {
        state.tunnel_snapshot.connected
    });
    (fixture, peer)
}

fn shutdown(fixture: &Fixture) {
    let tunnel = fixture.state().tunnel_service.clone();
    let executor = fixture.state().executor.clone();
    executor.block_on(tunnel.shutdown()).unwrap();
}

/// The focused element's key and whether it sits inside the account screen.
fn focus(fixture: &Fixture) -> Option<(String, bool)> {
    fixture
        .rt
        .elements()
        .into_iter()
        .find(|element| element.focused && !element.exiting)
        .map(|element| {
            (
                element.key.unwrap_or_default(),
                element.path.contains("account-screen"),
            )
        })
}

fn focused_key(fixture: &Fixture) -> Option<String> {
    focus(fixture).map(|(key, _)| key)
}

fn focus_in_account(fixture: &Fixture) -> bool {
    focus(fixture).is_some_and(|(_, inside)| inside)
}

/// Tabs to the control keyed `key`, failing when it never takes focus.
fn tab_to(fixture: &mut Fixture, key: &str) {
    for _ in 0..40 {
        if focused_key(fixture).as_deref() == Some(key) {
            return;
        }
        fixture.press(Key::Tab);
    }
    panic!("Tab never reached {key}; focus is on {:?}", focus(fixture));
}

fn space(fixture: &mut Fixture) {
    fixture.press(Key::Text(" ".into()));
}

/// Retries the dropped connection from the keyboard, as the locked screen offers.
fn retry(fixture: &mut Fixture) {
    assert!(fixture.state().account_locked());
    assert!(focus_in_account(fixture), "focus left the locked screen");
    tab_to(fixture, "retry-tunnel");
    space(fixture);
    fixture.wait("the tunnel to reconnect", |state| {
        state.tunnel_snapshot.connected
    });
}

#[test]
fn required_account_recovery_closes_the_editor_and_restores_the_workspace() {
    let (mut fixture, peer) = connected_fixture();
    fixture.click("directory-search");
    fixture.click("add-entry");
    assert!(matches!(fixture.state().editor, Some(Editor::User { .. })));
    fixture.type_text("troy.interrupted");
    peer.disconnect.send(()).unwrap();
    fixture.wait("the connection to drop", |state| {
        state.tunnel_snapshot.retry_available
    });
    assert!(fixture.state().editor.is_none());
    assert!(fixture.has("account-screen"));
    assert!(!fixture.has("workspace"));
    assert!(!fixture.has("close-account"));
    assert_eq!(
        fixture.text("account-title").as_deref(),
        Some("Connection interrupted")
    );
    fixture.press(Key::Escape);
    assert!(fixture.has("account-screen"), "Escape left a locked screen");
    retry(&mut fixture);
    assert!(!fixture.state().account_locked());
    assert!(fixture.has("workspace"));
    assert!(!fixture.has("account-screen"));
    assert!(fixture.state().editor.is_none());
    assert_eq!(focus(&fixture), Some(("account-settings".into(), false)));
    fixture.click("directory-search");
    fixture.type_text("Troy");
    assert_eq!(fixture.state().search.text, "Troy");
    assert!(
        !fixture
            .state()
            .directory()
            .unwrap()
            .users
            .iter()
            .any(|user| user.fields.username == "troy.interrupted")
    );
    shutdown(&fixture);
}

#[test]
fn account_connection_changes_keep_keyboard_focus_in_the_account_screen() {
    let (mut fixture, peer) = connected_fixture();
    assert_eq!(
        fixture.text("account-settings").as_deref(),
        Some("Signed in as @troy-barnes")
    );
    tab_to(&mut fixture, "account-settings");
    space(&mut fixture);
    assert!(fixture.state().account_open);
    assert!(focus_in_account(&fixture));
    assert_eq!(
        fixture.text("github-login").as_deref(),
        Some("Signed in as troy-barnes")
    );
    assert_eq!(
        fixture.text("public-url").as_deref(),
        Some("https://scimtest.example/greendale")
    );
    peer.disconnect.send(()).unwrap();
    fixture.wait("the connection to drop", |state| {
        state.tunnel_snapshot.retry_available
    });
    assert!(focus_in_account(&fixture));
    retry(&mut fixture);
    assert!(fixture.state().account_open);
    assert!(focus_in_account(&fixture));
    tab_to(&mut fixture, "close-account");
    space(&mut fixture);
    assert!(!fixture.state().account_open);
    assert_eq!(focused_key(&fixture).as_deref(), Some("account-settings"));
    space(&mut fixture);
    assert!(fixture.state().account_open);
    shutdown(&fixture);
}

#[test]
fn signing_out_rotates_the_installation_and_reconnects() {
    let (mut fixture, _peer) = connected_fixture();
    fixture.click("account-settings");
    fixture.click("sign-out-account");
    fixture.wait("the sign-out", |state| !state.account_busy);
    assert!(!fixture.state().failed, "{}", fixture.state().message);
    fixture.wait("the tunnel to reconnect", |state| {
        state.tunnel_snapshot.connected
    });
    assert!(fixture.has("account-screen"));
    shutdown(&fixture);
}

#[test]
fn account_screen_moves_focus_and_restores_the_previous_control() {
    let mut fixture = Fixture::new();
    fixture.click("directory-search");
    assert!(fixture.state().search.focused);
    fixture.rt.update(|state, _| state.account_open = true);
    fixture.settle();
    assert!(focus_in_account(&fixture));
    assert_eq!(
        fixture.text("account-title").as_deref(),
        Some("Local connection")
    );
    for shift in [false, true] {
        for _ in 0..8 {
            fixture.rt.key(rune::KeyEvent {
                key: Key::Tab,
                mods: rune::Mods {
                    shift,
                    ..Default::default()
                },
            });
            fixture.settle();
            assert!(focus_in_account(&fixture), "Tab left the account screen");
        }
    }
    fixture.rt.update(|state, _| state.account_open = false);
    fixture.settle();
    assert!(
        fixture.state().search.focused,
        "focus is on {:?}",
        focus(&fixture)
    );
    fixture.type_text("Troy");
    assert_eq!(fixture.state().search.text, "Troy");
}

#[test]
fn account_keyboard_round_trip_restores_the_toolbar_trigger() {
    let mut fixture = Fixture::new();
    tab_to(&mut fixture, "account-settings");
    space(&mut fixture);
    assert!(fixture.state().account_open);
    assert!(focus_in_account(&fixture));
    tab_to(&mut fixture, "close-account");
    space(&mut fixture);
    assert!(!fixture.state().account_open);
    assert_eq!(focused_key(&fixture).as_deref(), Some("account-settings"));
    space(&mut fixture);
    assert!(fixture.state().account_open);
    fixture.press(Key::Escape);
    assert!(!fixture.state().account_open, "Escape kept the screen open");
    assert_eq!(focused_key(&fixture).as_deref(), Some("account-settings"));
}

#[test]
fn exporting_a_connection_copies_or_saves_the_config() {
    let mut fixture = Fixture::new();
    let clipboard = rune::clipboard::memory();
    fixture.rt.use_clipboard(&clipboard);
    let environment = fixture.state().selected.clone().unwrap();
    let id = environment.clone();
    fixture
        .rt
        .update(move |state, tx| state.export_connection(id, Export::Config, false, tx));
    fixture.wait("the copy", |state| !state.busy);
    assert_eq!(fixture.state().message, "Config JSON copied");
    let copied: serde_json::Value =
        serde_json::from_str(&clipboard.text().expect("copied config")).unwrap();
    assert!(copied.is_object());

    let id = environment.clone();
    fixture
        .rt
        .update(move |state, tx| state.export_connection(id, Export::Config, true, tx));
    fixture.frame();
    let (_, options) = fixture.rt.file_dialog().expect("a save dialog");
    assert_eq!(
        options.file_name.as_deref(),
        Some("greendale-portal-config.json")
    );
    fixture.rt.resolve_file_dialog(None).unwrap();
    fixture.wait("the cancelled dialog", |state| !state.busy);
    assert!(fixture.state().message.is_empty());
    assert!(!fixture.state().failed);

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("greendale.json");
    fixture
        .rt
        .update(move |state, tx| state.export_connection(environment, Export::Config, true, tx));
    fixture.frame();
    fixture.rt.resolve_file_dialog(Some(path.clone())).unwrap();
    fixture.wait("the save", |state| !state.busy);
    assert_eq!(
        fixture.state().message,
        format!("Config saved to {}", path.display())
    );
    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(saved, copied);
}
