use rune::Key;

use super::Fixture;
use crate::workspace::{Editor, environment::Section};

fn wizard(fixture: &Fixture) -> (Section, String, bool) {
    let state = fixture.state();
    let Some(Editor::Environment { settings, .. }) = &state.editor else {
        panic!("the environment editor must be open");
    };
    (settings.section, state.message.clone(), state.failed)
}

#[test]
fn tabbing_moves_through_every_environment_field() {
    for (section, want) in [
        (Section::General, 3),
        (Section::Oidc, 11),
        (Section::Saml, 11),
        (Section::Scim, 2),
    ] {
        let mut fixture = Fixture::new();
        fixture.rt.update(move |state, _| {
            let environment = state
                .directory()
                .map(|directory| directory.environment.clone());
            state.edit_environment(environment.as_ref());
            if let Some(Editor::Environment { settings, .. }) = &mut state.editor {
                settings.section = section;
            }
            state
                .disclosures
                .extend(["oidc-claims", "saml-signing", "saml-mappings"]);
        });
        fixture.settle();
        for (key, shift) in [("tab", false), ("shift-tab", true)] {
            let mut visited = Vec::new();
            for _ in 0..72 {
                fixture.rt.key(rune::KeyEvent {
                    key: Key::Tab,
                    mods: rune::Mods {
                        shift,
                        ..Default::default()
                    },
                });
                fixture.frame();
                fixture.frame();
                let elements = fixture.rt.elements();
                let Some(focused) = elements.iter().find(|element| element.focused) else {
                    continue;
                };
                assert!(
                    elements
                        .iter()
                        .any(|element| element.key.as_deref() == Some("editor-dialog")
                            && focused.path.starts_with(&element.path)),
                    "{key}: focus left the editor for {}",
                    focused.path
                );
                if focused.role != "textbox" {
                    continue;
                }
                // Rune reveals focus in the nearest scroll view only, and a text area scrolls
                // itself, so only single-line fields are checked against the dialog's viewport.
                let [_, top, _, height] = focused.visible;
                assert!(
                    focused.path.contains("/scroll/")
                        || (height > 0.0 && top >= 0.0 && top + height <= 788.0),
                    "{key}: {} is out of view at {:?}",
                    focused.path,
                    focused.visible
                );
                if !visited.contains(&focused.path) {
                    visited.push(focused.path.clone());
                }
            }
            assert_eq!(visited.len(), want, "{section:?} {key}: {visited:#?}");
        }
    }
}

#[test]
fn environment_wizard_blocks_next_and_save_until_required_fields_are_set() {
    let mut fixture = Fixture::new();
    fixture.rt.update(|state, _| state.edit_environment(None));
    fixture.settle();
    fixture.click("wizard-next");
    let (step, message, failed) = wizard(&fixture);
    assert_eq!(step, Section::General);
    assert_eq!(message, "Enter an environment name.");
    assert!(failed);
    assert_eq!(
        fixture.text("editor-error").as_deref(),
        Some("Enter an environment name.")
    );

    fixture.click("environment-name/input");
    fixture.type_text("Troy Portal");
    fixture.click("wizard-next");
    let (step, _, failed) = wizard(&fixture);
    assert_eq!(step, Section::Oidc);
    assert!(!failed);

    fixture.click("oidc_enabled-switch");
    assert_eq!(
        fixture.text("oidc_enabled-state").as_deref(),
        Some("Enabled")
    );
    assert!(fixture.state().editor_dirty);
    fixture.click("step-0");
    assert_eq!(wizard(&fixture).0, Section::General);
    let directories = fixture.state().directories.len();
    fixture.click("save");
    let (step, message, failed) = wizard(&fixture);
    assert_eq!(step, Section::Oidc);
    assert_eq!(message, "OIDC needs Client ID, Redirect URIs.");
    assert!(failed);
    assert_eq!(fixture.state().directories.len(), directories);

    fixture.click("oidc_client_id/input");
    fixture.type_text("greendale-portal");
    fixture.click("oidc_redirect_uris/input");
    fixture.type_text("https://portal.greendale.edu/callback");
    fixture.click("step-4");
    assert_eq!(wizard(&fixture).0, Section::Review);
    assert_eq!(
        fixture.text("review-oidc_enabled").as_deref(),
        Some("OIDC: Enabled")
    );
    fixture.click("save");
    fixture.wait("the save", |state| !state.busy && state.editor.is_none());
    assert_eq!(fixture.state().message, "Environment saved");
    let saved = fixture
        .state()
        .directory()
        .expect("the new environment is selected")
        .environment
        .clone();
    assert_eq!(saved.name, "Troy Portal");
    assert_eq!(saved.settings.oidc_client_id, "greendale-portal");
    assert_eq!(
        saved.settings.oidc_redirect_uris,
        ["https://portal.greendale.edu/callback"]
    );
}

#[test]
fn choices_and_toggles_save_with_the_environment() {
    let mut fixture = Fixture::new();
    fixture.click("environment-settings");
    fixture.click("persona-picker");
    let okta = fixture
        .rt
        .elements()
        .into_iter()
        .find(|element| {
            element.label.as_deref() == Some("Okta") && element.role.starts_with("menuitem")
        })
        .and_then(|element| element.key)
        .expect("the Okta choice");
    fixture.click(&okta);
    assert_eq!(fixture.text("persona-picker").as_deref(), Some("Okta"));
    fixture.click("include_groups_claim");
    fixture.click("step-3");
    fixture.click("scim_enabled-switch");
    fixture.click("scim_base_url/input");
    fixture.type_text("https://portal.greendale.edu/scim/v2");
    fixture.click("scim_bearer_token/input");
    fixture.type_text("human-beings");
    fixture.click("scim_bearer_token/input/trailing/reveal");
    let reveal = fixture
        .rt
        .elements()
        .into_iter()
        .find(|element| {
            element
                .path
                .ends_with("scim_bearer_token/input/trailing/reveal")
        })
        .expect("the reveal button");
    assert_eq!(reveal.label.as_deref(), Some("Hide Bearer token"));
    fixture.click("save");
    fixture.wait("the save", |state| !state.busy && state.editor.is_none());
    let settings = &fixture
        .state()
        .directory()
        .expect("the environment is still selected")
        .environment
        .settings;
    assert_eq!(settings.persona, "okta");
    assert!(settings.include_groups_claim);
    assert!(settings.scim_enabled);
    assert_eq!(settings.scim_bearer_token, "human-beings");
}
