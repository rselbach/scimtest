use super::*;

#[test]
fn opening_another_lifecycle_form_starts_clean() {
    let mut fixture = Fixture::new();
    fixture.click("nav-Lifecycle");
    fixture.click("run-joiner");
    assert!(matches!(
        &fixture.state().editor,
        Some(Editor::Lifecycle(form)) if form.kind == "joiner"
    ));
    fixture.type_text("Troy");
    assert!(fixture.state().editor_dirty);
    fixture.click("lifecycle-kinds/mover");
    let Some(Editor::Lifecycle(form)) = &fixture.state().editor else {
        panic!("the mover form is open");
    };
    assert_eq!(form.kind, "mover");
    assert!(!form.user.is_empty(), "the mover starts on an active user");
    assert!(!fixture.state().editor_dirty);
    fixture.click("lifecycle-kinds/joiner");
    assert_eq!(fixture.state().scratch.text, "");
    let Some(Editor::Lifecycle(form)) = &fixture.state().editor else {
        panic!("the joiner form is open");
    };
    assert_eq!(form.values()[0], "", "the new form does not keep old edits");
    fixture.press(Key::Escape);
    assert!(fixture.state().editor.is_none());
}

#[test]
fn running_a_joiner_adds_a_run_to_the_lifecycle_page() {
    let mut fixture = Fixture::new();
    fixture.click("nav-Lifecycle");
    assert!(fixture.state().lifecycle.runs.is_empty());
    fixture.click("run-joiner");
    fixture.type_text("Garrett");
    fixture.click("lifecycle-field-1/input");
    fixture.type_text("Lambert");
    fixture.click("lifecycle-field-2/input");
    fixture.type_text("garrett.lambert@greendale.edu");
    fixture.click("lifecycle-field-3/input");
    fixture.type_text("glambert");
    let group = fixture.state().visible_groups()[0].id.clone();
    fixture.click(&format!("lifecycle-group-{group}"));
    fixture.click("save");
    fixture.wait("the joiner run", |state| {
        !state.busy && state.editor.is_none() && !state.lifecycle.runs.is_empty()
    });
    assert!(
        fixture
            .state()
            .message
            .starts_with("joiner scenario started for Garrett Lambert")
    );
    let run = fixture.state().lifecycle.runs[0].clone();
    assert_eq!(run.kind, "joiner");
    assert!(fixture.has(&run.id));
    assert_eq!(
        fixture.text("run-title").as_deref(),
        Some(format!("Joiner: {}", run.user).as_str())
    );
    assert!(fixture.has(&format!("{}/create", run.id)));
    let garrett = fixture.user_id("glambert");
    assert!(
        fixture
            .state()
            .visible_groups()
            .into_iter()
            .any(|saved| saved.id == group && saved.fields.member_ids.contains(&garrett))
    );
}

#[test]
fn running_a_mover_needs_a_user_and_changes_groups() {
    let mut fixture = Fixture::new();
    fixture.click("nav-Lifecycle");
    fixture.click("run-mover");
    let abed = fixture.user_id("anadir");
    fixture.click("lifecycle-user");
    let choice = fixture
        .rt
        .elements()
        .into_iter()
        .find(|element| {
            element.role.starts_with("menuitem")
                && element
                    .label
                    .as_deref()
                    .is_some_and(|label| label.starts_with("Abed"))
        })
        .and_then(|element| element.key)
        .expect("Abed's choice");
    fixture.click(&choice);
    let Some(Editor::Lifecycle(form)) = &fixture.state().editor else {
        panic!("the mover form is open");
    };
    assert_eq!(form.user, abed);
    let group = fixture
        .state()
        .visible_groups()
        .into_iter()
        .find(|group| !group.fields.member_ids.contains(&abed))
        .expect("a group Abed is not in");
    fixture.click(&format!("lifecycle-group-{}", group.id));
    fixture.click("save");
    fixture.wait("the mover run", |state| {
        !state.busy && state.editor.is_none() && !state.lifecycle.runs.is_empty()
    });
    let run = fixture.state().lifecycle.runs[0].clone();
    assert_eq!(run.kind, "mover");
    assert_eq!(run.user_id, abed);
    assert!(fixture.has(&run.id));
}

#[test]
fn running_a_leaver_deactivates_the_user() {
    let mut fixture = Fixture::new();
    fixture.click("nav-Lifecycle");
    fixture.click("run-leaver");
    let Some(Editor::Lifecycle(form)) = &fixture.state().editor else {
        panic!("the leaver form is open");
    };
    let user = form.user.clone();
    fixture.click("save");
    fixture.wait("the leaver run", |state| {
        !state.busy && state.editor.is_none() && !state.lifecycle.runs.is_empty()
    });
    assert_eq!(fixture.state().lifecycle.runs[0].kind, "leaver");
    fixture.wait("the deactivated user", |state| {
        state.directory().is_some_and(|directory| {
            directory
                .users
                .iter()
                .any(|saved| saved.id == user && !saved.fields.active)
        })
    });
}
