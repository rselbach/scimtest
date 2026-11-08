use rune::Key;

use super::{Fixture, oidc::reveal};
use crate::workspace::{Editor, connection::Export, environment::Section};

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

#[test]
fn oidc_and_saml_steps_list_the_values_to_copy_into_the_app() {
    let mut fixture = Fixture::new();
    let clipboard = rune::clipboard::memory();
    fixture.rt.use_clipboard(&clipboard);
    let environment = fixture.state().selected.clone().unwrap();
    let certificate = fixture
        .store
        .active_signing_key(&environment)
        .unwrap()
        .stored
        .certificate_pem;
    fixture.rt.update(|state, _| {
        let environment = state
            .directory()
            .map(|directory| directory.environment.clone());
        state.edit_environment(environment.as_ref());
        if let Some(Editor::Environment { settings, .. }) = &mut state.editor {
            settings.section = Section::Oidc;
        }
    });
    fixture.settle();
    let issuer = "http://127.0.0.1:1/oidc/greendale-portal";
    for (row, want) in [
        ("oidc-issuer", issuer.to_owned()),
        (
            "oidc-discovery",
            format!("{issuer}/.well-known/openid-configuration"),
        ),
        ("oidc-authorize", format!("{issuer}/authorize")),
        ("oidc-token", format!("{issuer}/token")),
        ("oidc-jwks", format!("{issuer}/jwks")),
    ] {
        assert_eq!(fixture.text(&format!("{row}-value")), Some(want.clone()));
        reveal(&mut fixture, "editor-content", &format!("{row}-copy"));
        fixture.click(&format!("{row}-copy"));
        assert_eq!(
            clipboard.text().as_deref().map(String::as_str),
            Some(want.as_str()),
            "{row}"
        );
    }
    assert!(fixture.has("save-oidc-config"));

    fixture.rt.update(|state, _| {
        if let Some(Editor::Environment { settings, .. }) = &mut state.editor {
            settings.section = Section::Saml;
        }
    });
    fixture.settle();
    let prefix = "http://127.0.0.1:1/saml/greendale-portal";
    for (row, want) in [
        ("saml-sso", format!("{prefix}/sso")),
        ("saml-slo", format!("{prefix}/slo")),
        ("saml-idp-entity", format!("{prefix}/metadata")),
        ("saml-certificate", certificate),
    ] {
        reveal(&mut fixture, "editor-content", &format!("{row}-copy"));
        fixture.click(&format!("{row}-copy"));
        assert_eq!(
            clipboard.text().as_deref().map(String::as_str),
            Some(want.as_str()),
            "{row}"
        );
    }
    assert!(fixture.has("save-saml-metadata"));
    assert!(fixture.has("save-saml-certificate"));
}

#[test]
fn a_new_environment_waits_for_an_endpoint_name_and_a_save() {
    let mut fixture = Fixture::new();
    fixture.rt.update(|state, _| {
        state.edit_environment(None);
        if let Some(Editor::Environment { settings, .. }) = &mut state.editor {
            settings.section = Section::Saml;
        }
    });
    fixture.settle();
    assert!(fixture.has("saml-sso-value"));
    assert_eq!(
        fixture.text("saml-sso-value").as_deref(),
        Some("Enter an endpoint name to generate this URL")
    );
    assert!(!fixture.has("save-saml-metadata"));
    assert_eq!(
        fixture.text("saml-certificate-value"),
        Some("Save the environment to show its signing certificate.".into())
    );

    fixture.rt.update(|state, _| {
        if let Some(Editor::Environment { name, .. }) = &mut state.editor {
            name.text = "Troy and Abed's Dreamatorium".into();
        }
    });
    fixture.settle();
    assert_eq!(
        fixture.text("saml-sso-value").as_deref(),
        Some("http://127.0.0.1:1/saml/troy-and-abed-s-dreamatorium/sso")
    );
}

#[test]
fn saml_metadata_and_certificate_save_to_the_chosen_files() {
    let mut fixture = Fixture::new();
    let environment = fixture.state().selected.clone().unwrap();
    let certificate = fixture
        .store
        .active_signing_key(&environment)
        .unwrap()
        .stored
        .certificate_pem;
    let directory = tempfile::tempdir().unwrap();
    for (export, file_name, saved) in [
        (
            Export::Metadata,
            "greendale-portal-idp-metadata.xml",
            "SAML metadata",
        ),
        (
            Export::Certificate,
            "greendale-portal-idp-certificate.pem",
            "Certificate",
        ),
    ] {
        let id = environment.clone();
        fixture
            .rt
            .update(move |state, tx| state.export_connection(id, export, true, tx));
        fixture.frame();
        let (_, options) = fixture.rt.file_dialog().expect("a save dialog");
        assert_eq!(options.file_name.as_deref(), Some(file_name));
        let path = directory.path().join(file_name);
        fixture.rt.resolve_file_dialog(Some(path.clone())).unwrap();
        fixture.wait("the save", |state| !state.busy);
        assert_eq!(
            fixture.state().message,
            format!("{saved} saved to {}", path.display())
        );
        let contents = std::fs::read_to_string(&path).unwrap();
        match export {
            Export::Metadata => assert!(
                contents
                    .contains(r#"entityID="http://127.0.0.1:1/saml/greendale-portal/metadata""#)
            ),
            _ => assert_eq!(contents, certificate),
        }
    }
}
