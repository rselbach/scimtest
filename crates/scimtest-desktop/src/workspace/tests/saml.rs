use super::{
    oidc::{choose, identity_fixture, shows},
    *,
};

fn run_saml(fixture: &mut Fixture) {
    let before = fixture.state().saml.inspections.len();
    fixture.click("add-entry");
    fixture.wait("the SAML sign-in", |state| {
        !state.busy && state.saml.inspections.len() > before && !state.identity_refreshing
    });
}

#[test]
fn a_saml_sign_in_shows_the_signed_response() {
    let mut fixture = identity_fixture();
    fixture.click("nav-SAML Inspector");
    assert!(shows(
        &fixture,
        "Run a sign-in to inspect the signed SAML response."
    ));
    assert!(fixture.has("saml-open-sign-in"));
    run_saml(&mut fixture);
    assert_eq!(fixture.state().message, "SAML response generated");
    assert!(!fixture.state().failed);
    assert!(fixture.has("saml-response-0"));
    assert!(fixture.has("saml-response-0/copy-saml-xml-0"));
    assert!(fixture.has("saml-response-0/SAML response"));
    assert!(!fixture.has("saml-response-0/faults"));
    fixture.click("Inspections");
    assert_eq!(fixture.state().saml.section, "Inspections");
    assert!(fixture.has("saml-response-0"));
    fixture.click("Flow activity");
    assert!(fixture.has("oidc-flow-0"));
}

#[test]
fn the_saml_fault_picker_tampers_with_the_next_response() {
    let mut fixture = identity_fixture();
    fixture.click("nav-SAML Inspector");
    fixture.click("saml-fault");
    choose(&mut fixture, "Wrong audience");
    assert_eq!(fixture.state().saml.fault, "Wrong audience");
    run_saml(&mut fixture);
    assert!(fixture.has("saml-response-0/faults"));
    let faults = fixture.text("faults").expect("the fault description");
    assert!(faults.to_lowercase().contains("audience"), "{faults}");
}

#[test]
fn logging_out_a_saml_session_opens_the_browser_and_lands_the_result() {
    let mut fixture = identity_fixture();
    fixture.click("nav-SAML Inspector");
    run_saml(&mut fixture);
    fixture.click("Sessions & logout");
    assert!(shows(&fixture, "No logout requests have been sent."));
    assert!(fixture.has("saml-session-0"));
    fixture.rt.take_url_requests();
    fixture.click("saml-logout-redirect-0");
    fixture.wait("the logout request", |state| {
        !state.busy && !state.saml.logouts.is_empty() && !state.identity_refreshing
    });
    assert_eq!(
        fixture.state().message,
        "Logout request opened in your browser"
    );
    let slug = fixture
        .state()
        .directory()
        .map(|directory| directory.environment.slug.clone())
        .expect("an environment");
    let opened = fixture.rt.take_url_requests();
    assert_eq!(opened.len(), 1, "{opened:?}");
    assert!(
        opened[0].starts_with(&format!(
            "{}/saml/{slug}/continue/",
            fixture.state().api_url
        )),
        "{opened:?}"
    );
    assert!(fixture.has("saml-logout-0"));
    assert!(shows(&fixture, "No live sessions with a SAML sign-in."));
}

#[test]
fn ending_a_saml_session_locally() {
    let mut fixture = identity_fixture();
    fixture.click("nav-SAML Inspector");
    run_saml(&mut fixture);
    fixture.click("Sessions & logout");
    fixture.click("saml-end-session-0");
    fixture.wait("the ended session", |state| {
        !state.busy && state.oidc.sessions.is_empty() && !state.identity_refreshing
    });
    assert_eq!(fixture.state().message, "Ended 1 sessions");
    assert!(shows(&fixture, "No live sessions with a SAML sign-in."));
    assert!(fixture.rt.take_url_requests().is_empty());
}
