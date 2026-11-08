use scimtest_core::configuration::SettingsPatch;

use super::*;

/// Turns on OIDC and SAML for the seeded environment and opens Fault Injection.
fn fault_injection() -> (Fixture, String) {
    let mut fixture = Fixture::new();
    let id = fixture.state().selected.clone().expect("an environment");
    fixture
        .store
        .update_environment(
            &id,
            EnvironmentPatch {
                settings: SettingsPatch {
                    oidc_enabled: Some(true),
                    saml_enabled: Some(true),
                    oidc_redirect_uris: Some(vec!["https://portal.greendale.edu/callback".into()]),
                    saml_entity_id: Some("https://portal.greendale.edu".into()),
                    saml_acs_url: Some("https://portal.greendale.edu/saml/acs".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .expect("enable OIDC and SAML");
    fixture.wait("the identity settings", |state| {
        state
            .directory()
            .is_some_and(|directory| directory.environment.settings.supports_saml())
    });
    fixture
        .store
        .signing_key_views(&id)
        .expect("create the signing keys before the page loads them");
    fixture.click("nav-Fault Injection");
    fixture.wait("the presets", |state| !state.resilience.presets.is_empty());
    (fixture, id)
}

fn menu_item(fixture: &Fixture, label: &str) -> String {
    fixture
        .rt
        .elements()
        .into_iter()
        .find(|element| {
            element.label.as_deref() == Some(label) && element.role.starts_with("menuitem")
        })
        .and_then(|element| element.key)
        .unwrap_or_else(|| panic!("no menu item {label}"))
}

#[test]
fn arming_a_preset_arms_the_identity_with_the_chosen_count() {
    let (mut fixture, id) = fault_injection();
    assert!(fixture.has("preset-token-outage"));
    assert!(fixture.has("preset-stale-jwks"));
    fixture.click("count-token-outage");
    let five = menu_item(&fixture, "5");
    fixture.click(&five);
    assert_eq!(
        fixture.state().resilience.counts.get("token-outage"),
        Some(&5)
    );
    fixture.click("arm-token-outage");
    fixture.wait("the armed scenario", |state| {
        !state.busy && state.resilience_active()
    });
    assert_eq!(fixture.state().message, "Armed Token endpoint outage");
    let run = fixture
        .state()
        .identity
        .resilience_run(&id)
        .expect("read the run")
        .expect("a run is armed");
    assert_eq!(run.preset_id, "token-outage");
    assert_eq!(run.total, 5);
    assert!(run.active());
    assert!(fixture.has("resilience-run"));
    assert_eq!(
        fixture.text("add-entry").as_deref(),
        Some("Disarm scenario")
    );
}

#[test]
fn disarming_clears_the_armed_scenario() {
    let (mut fixture, id) = fault_injection();
    fixture.click("arm-stale-jwks");
    fixture.wait("the armed scenario", |state| {
        !state.busy && state.resilience_active()
    });
    fixture.click("add-entry");
    fixture.wait("the disarm", |state| {
        !state.busy && !state.resilience_active()
    });
    assert_eq!(fixture.state().message, "Fault injection scenario disarmed");
    let run = fixture
        .state()
        .identity
        .resilience_run(&id)
        .expect("read the run");
    assert!(!run.is_some_and(|run| run.active()));
}

#[test]
fn custom_faults_save_through_the_identity() {
    let (mut fixture, id) = fault_injection();
    fixture.click("custom-faults");
    assert!(matches!(fixture.state().editor, Some(Editor::Faults(_))));
    fixture.click("fault-field-2/input");
    fixture.type_text("5m");
    fixture.click("wrong_issuer");
    fixture.click("fault-saml-status");
    let responder = menu_item(&fixture, "Responder");
    fixture.click(&responder);
    assert!(fixture.state().editor_dirty);
    fixture.click("save");
    fixture.wait("the armed faults", |state| {
        !state.busy && state.editor.is_none() && state.resilience.manual.active()
    });
    assert_eq!(
        fixture.state().message,
        "Custom faults armed for the next matching flow"
    );
    let faults = fixture
        .state()
        .identity
        .faults(&id)
        .expect("read the faults");
    assert!(faults.clock_skew.is_some());
    assert_eq!(faults.tamper, ["wrong_issuer"]);
    assert_eq!(faults.saml_status, "Responder");
    assert!(fixture.has("manual-fault"));
    fixture.click("clear-manual-fault");
    fixture.wait("the cleared faults", |state| {
        !state.busy && !state.resilience.manual.active()
    });
    assert_eq!(fixture.state().message, "Armed faults cleared");
}

#[test]
fn custom_faults_need_at_least_one_fault() {
    let (mut fixture, _) = fault_injection();
    fixture.click("custom-faults");
    fixture.click("save");
    assert!(fixture.state().failed);
    assert_eq!(fixture.state().message, "Choose at least one fault");
    assert!(fixture.has("editor-error"));
    assert!(fixture.state().editor.is_some());
}
