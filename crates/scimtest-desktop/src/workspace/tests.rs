mod account;
mod environment;
mod lifecycle;
mod oidc;
mod resilience;
mod saml;
mod scim;
mod tools;
mod traffic;

use std::{sync::mpsc, time::Duration};

use rune::{Env, Key, KeyEvent, Mods, Runtime};

use super::*;

/// A workspace on a seeded Greendale store, driven through Rune's headless runtime.
pub(crate) struct Fixture {
    pub rt: Runtime<Workspace>,
    updates: mpsc::Receiver<Update>,
    time: f64,
    pub store: Store,
    _directory: tempfile::TempDir,
    _executor: tokio::runtime::Runtime,
}

impl Fixture {
    pub fn new() -> Self {
        Self::with_tunnel(None)
    }

    pub fn with_tunnel(config: Option<scimtest_core::tunnel::Config>) -> Self {
        let directory = tempfile::tempdir().expect("create a temporary directory");
        let store = Store::open(&directory.path().join("state.db")).expect("open the store");
        let environment = store
            .create_environment(EnvironmentInput {
                name: "Greendale Portal".into(),
                ..Default::default()
            })
            .expect("create an environment");
        store
            .seed_sample(&environment.id)
            .expect("seed the Greendale sample");
        let executor = tokio::runtime::Runtime::new().expect("start tokio");
        let tunnel = {
            let _entered = executor.enter();
            scimtest_core::tunnel::Service::new(store.clone(), config, 1)
                .expect("start the tunnel service")
        };
        let (sender, updates) = mpsc::channel::<Update>();
        let workspace = Workspace::new(Services {
            identity: scimtest_core::oidc::Identity::new(store.clone()),
            scim: scimtest_core::scim::Service::new(store.clone()),
            tunnel,
            executor: executor.handle().clone(),
            api_url: "http://127.0.0.1:1".into(),
            updates: crate::updates::Controller::new(None, store.clone()),
            lander: Lander::new(move |update| {
                let _ = sender.send(update);
            }),
            shell: None,
            store: store.clone(),
        });
        let mut rt = Runtime::new(
            workspace,
            view,
            (1280.0, 788.0),
            Env {
                system_dark: true,
                scale: 1.0,
            },
        );
        rt.frame(0.0);
        Self {
            rt,
            updates,
            time: 0.0,
            store,
            _directory: directory,
            _executor: executor,
        }
    }

    pub fn state(&self) -> &Workspace {
        &self.rt.state
    }

    pub fn frame(&mut self) {
        self.time += 1.0 / 60.0;
        self.rt.frame(self.time);
    }

    /// Runs frames until animations such as a dialog's entrance have landed.
    pub fn settle(&mut self) {
        for _ in 0..60 {
            self.frame();
        }
    }

    /// Applies the background results that have arrived.
    pub fn land(&mut self) {
        while let Ok(update) = self.updates.try_recv() {
            self.rt.update(move |state, tx| {
                update(state, tx);
            });
        }
        self.frame();
    }

    /// Lands background results until `done` holds.
    pub fn wait(&mut self, what: &str, done: impl Fn(&Workspace) -> bool) {
        for _ in 0..500 {
            self.land();
            if done(&self.rt.state) {
                self.settle();
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out waiting for {what}");
    }

    pub fn has(&self, key: &str) -> bool {
        self.rt.find(key).is_some()
    }

    pub fn click(&mut self, key: &str) {
        let Some((x, y)) = self.rt.find(key) else {
            panic!("no element keyed {key}");
        };
        self.rt.pointer_down(x, y);
        self.rt.pointer_up(x, y);
        self.settle();
    }

    pub fn press(&mut self, key: Key) {
        self.rt.key(KeyEvent {
            key,
            mods: Mods::default(),
        });
        self.settle();
    }

    pub fn type_text(&mut self, text: &str) {
        self.rt.key(KeyEvent {
            key: Key::Text(text.into()),
            mods: Mods::default(),
        });
        self.settle();
    }

    /// The text shown by the first element whose key is `key`.
    pub fn text(&self, key: &str) -> Option<String> {
        self.rt
            .elements()
            .into_iter()
            .find(|element| element.key.as_deref() == Some(key) && !element.exiting)
            .and_then(|element| element.text.or(element.label))
    }

    pub fn user_id(&self, username: &str) -> String {
        self.state()
            .directory()
            .and_then(|directory| {
                directory
                    .users
                    .iter()
                    .find(|user| user.fields.username == username)
            })
            .map(|user| user.id.clone())
            .unwrap_or_else(|| panic!("no user {username}"))
    }
}

#[test]
fn the_seeded_directory_lists_users_and_search_filters_them() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.state().visible_users().len(), 10);
    let troy = fixture.user_id("tbarnes");
    assert!(fixture.has(&troy));
    fixture.click("directory-search");
    fixture.type_text("abed");
    assert_eq!(fixture.state().search.text, "abed");
    assert_eq!(fixture.state().visible_users().len(), 1);
    assert!(!fixture.has(&troy));
    assert_eq!(
        fixture.text("table-range").as_deref(),
        Some("Showing 1–1 of 1")
    );
}

#[test]
fn editing_a_user_saves_through_the_store() {
    let mut fixture = Fixture::new();
    let troy = fixture.user_id("anadir");
    fixture.click(&format!("edit-{troy}"));
    assert!(matches!(fixture.state().editor, Some(Editor::User { .. })));
    assert!(fixture.has("editor-dialog"));
    fixture.click("user-enterprise");
    fixture.click("field-8/input");
    fixture.type_text("Air Conditioning Repair Annex");
    assert!(fixture.state().editor_dirty);
    fixture.click("save");
    fixture.wait("the save", |state| !state.busy && state.editor.is_none());
    assert_eq!(fixture.state().message, "User saved");
    assert!(!fixture.state().failed);
    let saved = fixture
        .store
        .snapshot()
        .expect("read the store")
        .into_iter()
        .flat_map(|directory| directory.users)
        .find(|user| user.id == troy)
        .expect("Abed is still there");
    assert!(
        saved
            .fields
            .department
            .ends_with("Air Conditioning Repair Annex")
    );
}

#[test]
fn escape_closes_a_clean_editor_and_guards_a_changed_one() {
    let mut fixture = Fixture::new();
    fixture.click("add-entry");
    assert!(fixture.state().editor.is_some());
    fixture.press(Key::Escape);
    assert!(fixture.state().editor.is_none());
    fixture.click("add-entry");
    fixture.type_text("troy");
    fixture.press(Key::Escape);
    assert!(fixture.state().discarding, "a changed editor asks first");
    assert!(fixture.has("discard-dialog"));
    fixture.click("cancel-discard");
    assert!(!fixture.state().discarding);
    assert!(fixture.state().editor.is_some(), "cancel keeps the edits");
    fixture.press(Key::Escape);
    fixture.click("confirm-discard");
    assert!(fixture.state().editor.is_none());
}

#[test]
fn group_members_toggle_and_save() {
    let mut fixture = Fixture::new();
    fixture.click("nav-Groups");
    let group = fixture.state().visible_groups()[0].clone();
    let before = group.fields.member_ids.len();
    fixture.click(&format!("edit-{}", group.id));
    let abed = fixture.user_id("anadir");
    let joined = !group.fields.member_ids.contains(&abed);
    fixture.click(&format!("member-row-{abed}/member"));
    fixture.click("save");
    fixture.wait("the save", |state| !state.busy && state.editor.is_none());
    assert_eq!(fixture.state().message, "Group saved");
    let saved = fixture
        .state()
        .visible_groups()
        .into_iter()
        .find(|saved| saved.id == group.id)
        .expect("the group is still there");
    assert_eq!(
        saved.fields.member_ids.len(),
        if joined { before + 1 } else { before - 1 }
    );
}

#[test]
fn deleting_a_user_asks_first_and_selection_deletes_in_bulk() {
    let mut fixture = Fixture::new();
    let chang = fixture.user_id("schang");
    fixture.click(&format!("remove-{chang}"));
    assert!(matches!(
        fixture.state().editor,
        Some(Editor::Delete { .. })
    ));
    fixture.click("save");
    fixture.wait("the delete", |state| !state.busy && state.editor.is_none());
    assert_eq!(fixture.state().message, "Deleted");
    let abed = fixture.user_id("anadir");
    let annie = fixture.user_id("aedison");
    fixture.click(&format!("select-{abed}"));
    fixture.click(&format!("select-{annie}"));
    assert_eq!(fixture.state().selected_rows.len(), 2);
    assert_eq!(
        fixture.text("selection-count").as_deref(),
        Some("2 users selected")
    );
    fixture.click("delete-selected");
    fixture.click("save");
    fixture.wait("the bulk delete", |state| {
        !state.busy && state.editor.is_none()
    });
    assert_eq!(fixture.state().message, "Deleted 2 entries");
    assert!(fixture.state().selected_rows.is_empty());
}

#[test]
fn the_status_filter_and_page_size_menus_change_the_rows() {
    let mut fixture = Fixture::new();
    fixture.click("status-filter");
    assert_eq!(fixture.state().open_menu.as_deref(), Some("status-filter"));
    let inactive = fixture
        .rt
        .elements()
        .into_iter()
        .find(|element| {
            element.label.as_deref() == Some("Inactive") && element.role.starts_with("menuitem")
        })
        .and_then(|element| element.key)
        .expect("the Inactive choice");
    fixture.click(&inactive);
    assert_eq!(fixture.state().status_filter, "Inactive");
    assert!(fixture.state().open_menu.is_none());
    assert_eq!(fixture.state().visible_users().len(), 1);
}

#[test]
fn shortcuts_focus_search_and_save_the_open_editor() {
    let mut fixture = Fixture::new();
    fixture.rt.update(|state, _| state.focus_search());
    fixture.settle();
    fixture.type_text("britta");
    assert_eq!(fixture.state().search.text, "britta");
    let britta = fixture.user_id("bperry");
    fixture.click(&format!("edit-{britta}"));
    fixture.rt.update(|state, _| state.save_shortcut());
    fixture.wait("the save", |state| !state.busy && state.editor.is_none());
    assert_eq!(fixture.state().message, "User saved");
}
