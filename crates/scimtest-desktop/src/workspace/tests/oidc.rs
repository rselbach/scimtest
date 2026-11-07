use scimtest_core::configuration::SettingsPatch;

use super::*;

/// A fixture whose Greendale environment speaks OIDC and SAML, with the workspace's own
/// identity provider served on a local port so the playground runs real HTTP exchanges.
pub(super) fn identity_fixture() -> Fixture {
    let mut fixture = Fixture::new();
    let id = fixture.state().selected.clone().expect("an environment");
    fixture
        .store
        .update_environment(
            &id,
            EnvironmentPatch {
                settings: SettingsPatch {
                    oidc_enabled: Some(true),
                    oidc_client_id: Some("greendale-portal".into()),
                    oidc_client_secret: Some("senor-chang".into()),
                    saml_enabled: Some(true),
                    saml_entity_id: Some("urn:greendale:sp".into()),
                    saml_acs_url: Some("https://greendale.example/acs".into()),
                    saml_slo_url: Some("https://greendale.example/slo".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .expect("enable OIDC and SAML");
    fixture
        .store
        .active_signing_key(&id)
        .expect("generate the signing key");
    let listener = fixture
        ._executor
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .expect("bind the issuer");
    let address = listener.local_addr().expect("read the issuer address");
    let router = scimtest_core::api::router_with_identity(
        fixture.store.clone(),
        "greendale-token".into(),
        address.to_string(),
        fixture.state().identity.clone(),
    );
    fixture._executor.spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("serve the issuer");
    });
    fixture.rt.state.api_url = format!("http://{address}");
    fixture.wait("the protocols to show", |state| {
        state
            .directory()
            .is_some_and(|directory| directory.environment.settings.supports_saml())
    });
    fixture
}

/// Scrolls `scroll` until the element keyed `key` is in view, so a click lands on it.
pub(super) fn reveal(fixture: &mut Fixture, scroll: &str, key: &str) {
    let ([_, top, _, height], _) = fixture.rt.presented(scroll).expect("the scroll area");
    for _ in 0..40 {
        let (_, y) = fixture
            .rt
            .find(key)
            .unwrap_or_else(|| panic!("no element keyed {key}"));
        if (top..top + height).contains(&y) {
            return;
        }
        let (x, middle) = fixture.rt.find(scroll).expect("the scroll area");
        fixture
            .rt
            .wheel(x, middle, if y < top { 150.0 } else { -150.0 });
        fixture.settle();
    }
    panic!("could not scroll {key} into view");
}

/// Whether some element shows exactly `text`.
pub(super) fn shows(fixture: &Fixture, text: &str) -> bool {
    fixture
        .rt
        .elements()
        .into_iter()
        .any(|element| element.text.as_deref() == Some(text) && !element.exiting)
}

/// Picks the menu item labelled `label` from the open dropdown.
pub(super) fn choose(fixture: &mut Fixture, label: &str) {
    let key = fixture
        .rt
        .elements()
        .into_iter()
        .find(|element| {
            element.label.as_deref() == Some(label) && element.role.starts_with("menuitem")
        })
        .and_then(|element| element.key)
        .unwrap_or_else(|| panic!("no menu item {label}"));
    fixture.click(&key);
}

fn run_oidc(fixture: &mut Fixture) {
    fixture.click("run-oidc");
    assert!(fixture.state().busy);
    fixture.wait("the sign-in", |state| {
        !state.busy && state.oidc.result.is_some() && !state.identity_refreshing
    });
}

#[test]
fn a_playground_sign_in_shows_its_tokens_and_the_inspections() {
    let mut fixture = identity_fixture();
    fixture.click("nav-OIDC Inspector");
    assert!(fixture.has("oidc-browser-playground"));
    assert!(!fixture.has("ID token claims"));
    run_oidc(&mut fixture);
    assert_eq!(fixture.state().message, "Sign-in completed");
    assert!(!fixture.state().failed);
    let statuses = fixture.text("oidc-result-statuses").expect("the statuses");
    assert!(statuses.contains("Token 200"), "{statuses}");
    assert!(statuses.contains("Userinfo 200"), "{statuses}");
    assert!(fixture.has("ID token claims"));
    assert!(fixture.has("Userinfo"));
    assert!(fixture.has("copy-oidc-result"));
    reveal(&mut fixture, "oidc-scroll", "oidc-inspections");
    fixture.click("oidc-inspections");
    assert!(!fixture.state().oidc.inspections.is_empty());
    assert!(fixture.has("oidc-inspection-0"));
    assert!(fixture.has("oidc-inspection-0/copy-token-0"));
    reveal(&mut fixture, "oidc-scroll", "oidc-flows");
    fixture.click("oidc-flows");
    assert!(fixture.has("oidc-flow-0"));
    reveal(&mut fixture, "oidc-scroll", "oidc-sessions");
    fixture.click("oidc-sessions");
    assert!(fixture.has("token-holder-0"));
    assert!(fixture.has("browser-session-0"));
    reveal(&mut fixture, "oidc-scroll", "oidc-revoke-all");
    fixture.click("oidc-revoke-all");
    fixture.wait("the revocation", |state| {
        !state.busy && state.oidc.holders.is_empty() && !state.identity_refreshing
    });
    assert!(
        fixture.state().message.starts_with("Revoked "),
        "{}",
        fixture.state().message
    );
    assert!(shows(&fixture, "No live user tokens."));
}

#[test]
fn the_fault_picker_changes_the_next_sign_in() {
    let mut fixture = identity_fixture();
    fixture.click("nav-OIDC Inspector");
    fixture.click("oidc-fault");
    choose(&mut fixture, "Missing email");
    assert_eq!(fixture.state().oidc.fault, "Missing email");
    assert_eq!(fixture.text("oidc-fault").as_deref(), Some("Missing email"));
    run_oidc(&mut fixture);
    let result = fixture.state().oidc.result.clone().expect("a result");
    assert!(result["id_token_claims"].get("email").is_none(), "{result}");
    reveal(&mut fixture, "oidc-scroll", "oidc-inspections");
    fixture.click("oidc-inspections");
    assert!(fixture.has("oidc-inspection-0/faults"));
    reveal(&mut fixture, "oidc-scroll", "oidc-fault");
    fixture.click("oidc-fault");
    choose(&mut fixture, "Healthy sign-in");
    assert_eq!(fixture.state().oidc.fault, "");
    run_oidc(&mut fixture);
    let result = fixture.state().oidc.result.clone().expect("a result");
    assert!(result["id_token_claims"].get("email").is_some(), "{result}");
}

#[test]
fn the_account_picker_signs_in_as_the_chosen_user() {
    let mut fixture = identity_fixture();
    fixture.click("nav-OIDC Inspector");
    fixture.click("oidc-account");
    choose(&mut fixture, "Troy Barnes · troy.barnes@greendale.edu");
    assert_eq!(fixture.state().oidc.user, fixture.user_id("tbarnes"));
    run_oidc(&mut fixture);
    let result = fixture.state().oidc.result.clone().expect("a result");
    assert_eq!(result["userinfo"]["name"], "Troy Barnes", "{result}");
}

#[test]
fn rotating_the_signing_key_keeps_the_old_one_published() {
    let mut fixture = identity_fixture();
    fixture.click("nav-OIDC Inspector");
    fixture.wait("the keys", |state| !state.oidc.keys.is_empty());
    let before = fixture.state().oidc.keys.len();
    fixture.click("rotate-key");
    choose(&mut fixture, "Standard certificate · 24 hour grace");
    // generating the new RSA key can outlast `wait` in a debug build
    for _ in 0..3000 {
        fixture.land();
        if !fixture.state().busy {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    fixture.wait("the rotation", |state| {
        !state.busy && state.oidc.keys.len() == before + 1 && !state.identity_refreshing
    });
    assert_eq!(fixture.state().message, "Signing key rotated");
    let keys = &fixture.state().oidc.keys;
    assert!(keys[0].active && !keys[1].active);
    let retired = keys[1].kid.clone();
    assert!(fixture.has(&format!("{retired}/copy-certificate-1")));
}

#[test]
fn arming_the_selected_fault_and_clearing_it() {
    let mut fixture = identity_fixture();
    fixture.click("nav-OIDC Inspector");
    assert!(fixture.rt.state.oidc.fault.is_empty());
    fixture.click("arm-fault");
    assert!(!fixture.state().busy, "healthy sign-in has nothing to arm");
    fixture.click("oidc-fault");
    choose(&mut fixture, "Broken signature");
    fixture.click("arm-fault");
    fixture.wait("the armed fault", |state| !state.busy);
    assert_eq!(fixture.state().message, "Fault armed for the next sign-in");
    let id = fixture.state().selected.clone().expect("an environment");
    let armed = fixture
        .state()
        .identity
        .faults(&id)
        .expect("read the faults");
    assert!(armed.break_signature);
    fixture.click("clear-faults");
    fixture.wait("the cleared faults", |state| !state.busy);
    assert_eq!(fixture.state().message, "Armed faults cleared");
    let armed = fixture
        .state()
        .identity
        .faults(&id)
        .expect("read the faults");
    assert!(!armed.break_signature);
}
