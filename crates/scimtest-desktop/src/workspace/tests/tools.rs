use rune::{FileDialogKind, TextEdit};

use super::Fixture;
use crate::workspace::Editor;

/// Opens the bulk tools from the sidebar.
fn tools() -> Fixture {
    let mut fixture = Fixture::new();
    fixture.click("bulk-tools");
    assert!(matches!(fixture.state().editor, Some(Editor::Tools { .. })));
    fixture
}

/// Scrolls the open editor until `key` is in view, then clicks it.
fn reveal_and_click(fixture: &mut Fixture, key: &str) {
    let Some((x, y)) = fixture.rt.find("editor-content") else {
        panic!("no editor is open");
    };
    for _ in 0..20 {
        let visible = fixture
            .rt
            .elements()
            .into_iter()
            .find(|element| element.key.as_deref() == Some(key) && !element.exiting)
            .map(|element| element.visible)
            .unwrap_or_else(|| panic!("no element keyed {key}"));
        if visible[3] > 0.0 && visible[1] + visible[3] < 700.0 {
            fixture.click(key);
            return;
        }
        fixture.rt.wheel(x, y, -120.0);
        fixture.settle();
    }
    panic!("{key} never scrolled into view");
}

fn finish(fixture: &mut Fixture) -> String {
    fixture.wait("the tool", |state| !state.busy && state.editor.is_none());
    assert!(!fixture.state().failed, "{}", fixture.state().message);
    fixture.state().message.clone()
}

fn set_count(fixture: &mut Fixture, value: &'static str) {
    fixture.rt.update(move |state, _| {
        if let Some(Editor::Tools { count, .. }) = &mut state.editor {
            *count = TextEdit::new(value);
        }
    });
    fixture.settle();
}

#[test]
fn create_users_adds_the_requested_number() {
    let mut fixture = tools();
    set_count(&mut fixture, "3");
    fixture.click("create-users");
    assert_eq!(finish(&mut fixture), "Created 3 users");
    assert_eq!(fixture.state().visible_users().len(), 13);
    let created = fixture
        .state()
        .visible_users()
        .into_iter()
        .filter(|user| user.fields.email.ends_with("@greendale.edu"))
        .count();
    assert!(created >= 3);
}

#[test]
fn create_users_rejects_a_count_that_is_not_a_number() {
    let mut fixture = tools();
    set_count(&mut fixture, "a lot");
    fixture.click("create-users");
    fixture.wait("the failure", |state| !state.busy && state.failed);
    assert_eq!(
        fixture.state().message,
        "Number of users must be between 1 and 10000"
    );
    assert!(matches!(fixture.state().editor, Some(Editor::Tools { .. })));
    assert!(fixture.has("editor-error"));
}

#[test]
fn bulk_actions_deactivate_and_activate_every_user() {
    let mut fixture = tools();
    fixture.click("deactivate-all");
    assert_eq!(finish(&mut fixture), "Changed 9 users");
    assert!(
        fixture
            .state()
            .visible_users()
            .iter()
            .all(|user| !user.fields.active)
    );
    fixture.click("bulk-tools");
    fixture.click("activate-all");
    assert_eq!(finish(&mut fixture), "Changed 10 users");
    assert!(
        fixture
            .state()
            .visible_users()
            .iter()
            .all(|user| user.fields.active)
    );
}

#[test]
fn delete_all_and_clear_local_ask_first() {
    let mut fixture = tools();
    fixture.click("delete-all");
    assert!(matches!(
        fixture.state().editor,
        Some(Editor::ConfirmTool {
            action: "delete-all"
        })
    ));
    assert!(
        fixture
            .text("tool-question")
            .is_some_and(|text| text.starts_with("Delete every user in this environment?"))
    );
    fixture.click("cancel");
    assert!(fixture.state().editor.is_none());
    assert_eq!(fixture.state().visible_users().len(), 10);

    fixture.click("bulk-tools");
    fixture.click("delete-all");
    fixture.click("save");
    assert!(finish(&mut fixture).starts_with("Changed 10 users"));
    assert!(fixture.state().visible_users().is_empty());

    fixture.click("bulk-tools");
    fixture.click("clear-local");
    assert!(
        fixture
            .text("tool-question")
            .is_some_and(|text| text.starts_with("Remove all local users, groups"))
    );
    fixture.click("save");
    finish(&mut fixture);
    let directory = fixture.state().directory().expect("the environment stays");
    assert!(directory.users.is_empty());
    assert!(directory.groups.is_empty());
}

#[test]
fn the_greendale_sample_loads_once() {
    let mut fixture = tools();
    fixture.click("seed");
    assert_eq!(finish(&mut fixture), "Added 0 users and 0 groups");
}

#[test]
fn a_backup_exports_and_restores_through_file_dialogs() {
    let directory = tempfile::tempdir().expect("create a temporary directory");
    let path = directory.path().join("greendale-backup.json");
    let mut fixture = tools();
    reveal_and_click(&mut fixture, "backup");
    let (kind, options) = fixture.rt.file_dialog().expect("a save dialog");
    assert_eq!(kind, FileDialogKind::Save);
    assert!(
        options
            .file_name
            .as_deref()
            .is_some_and(|name| name.ends_with("-backup.json"))
    );
    fixture
        .rt
        .resolve_file_dialog(Some(path.clone()))
        .expect("answer the dialog");
    assert_eq!(
        finish(&mut fixture),
        format!("Backup saved to {}", path.display())
    );
    assert!(path.exists());

    let troy = fixture.user_id("tbarnes");
    let environment = fixture.state().selected.clone().expect("an environment");
    fixture
        .store
        .delete_user(&environment, &troy)
        .expect("delete Troy");
    fixture.wait("the deletion", |state| state.visible_users().len() == 9);

    fixture.click("bulk-tools");
    reveal_and_click(&mut fixture, "restore");
    let (kind, _) = fixture.rt.file_dialog().expect("an open dialog");
    assert_eq!(kind, FileDialogKind::Open);
    fixture
        .rt
        .resolve_file_dialog(Some(path))
        .expect("answer the dialog");
    fixture.wait("the backup", |state| {
        matches!(state.editor, Some(Editor::RestoreBackup { .. }))
    });
    assert!(
        fixture
            .text("restore-question")
            .is_some_and(|text| text.contains("10 users and 3 groups"))
    );
    fixture.click("save");
    assert!(finish(&mut fixture).starts_with("Backup restored; previous state saved to "));
    assert_eq!(fixture.state().visible_users().len(), 10);
}

#[test]
fn restoring_refuses_a_backup_of_another_environment() {
    let directory = tempfile::tempdir().expect("create a temporary directory");
    let path = directory.path().join("city-college.json");
    let mut fixture = tools();
    let mut backup = serde_json::to_value(
        fixture
            .store
            .backup(fixture.state().selected.as_deref().expect("an environment"))
            .expect("back up"),
    )
    .expect("serialize the backup");
    backup["state"]["environment"]["id"] = "city-college".into();
    std::fs::write(&path, backup.to_string()).expect("write the backup");
    reveal_and_click(&mut fixture, "restore");
    fixture
        .rt
        .resolve_file_dialog(Some(path))
        .expect("answer the dialog");
    fixture.wait("the refusal", |state| state.failed);
    assert_eq!(
        fixture.state().message,
        "Choose a version 1 backup for the selected environment"
    );
    assert!(matches!(fixture.state().editor, Some(Editor::Tools { .. })));
}

#[test]
fn cancelling_a_file_dialog_changes_nothing() {
    let mut fixture = tools();
    reveal_and_click(&mut fixture, "restore");
    fixture
        .rt
        .resolve_file_dialog(None)
        .expect("cancel the dialog");
    fixture.settle();
    assert!(!fixture.state().failed);
    assert!(matches!(fixture.state().editor, Some(Editor::Tools { .. })));
}
