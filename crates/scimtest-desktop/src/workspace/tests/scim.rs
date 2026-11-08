use std::net::SocketAddr;

use axum::{
    Json, Router,
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use scimtest_core::configuration::SettingsPatch;
use serde_json::{Value, json};

use super::*;

/// Serves the router `build` makes for its address, on a loopback port of the fixture's runtime.
pub(super) fn serve(fixture: &Fixture, build: impl FnOnce(SocketAddr) -> Router) -> SocketAddr {
    let handle = fixture.state().executor.clone();
    let _entered = handle.enter();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    listener
        .set_nonblocking(true)
        .expect("make the listener non-blocking");
    let address = listener.local_addr().expect("read the bound address");
    let router = build(address);
    let listener = tokio::net::TcpListener::from_std(listener).expect("hand the listener to tokio");
    handle.spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("serve the router");
    });
    address
}

/// A SCIM target that creates whatever it is sent and lists nothing.
async fn remote(request: Request) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_owned();
    let bytes = axum::body::to_bytes(request.into_body(), 1 << 20)
        .await
        .expect("read the request body");
    match method.as_str() {
        "GET" if path == "/ServiceProviderConfig" => {
            Json(json!({"patch":{"supported":true},"filter":{"supported":true}})).into_response()
        }
        "GET" => Json(json!({"totalResults":0,"startIndex":1,"Resources":[]})).into_response(),
        "POST" => {
            let mut resource: Value = serde_json::from_slice(&bytes).expect("a JSON resource");
            resource["id"] = json!(format!(
                "remote-{}",
                resource["externalId"].as_str().unwrap_or_default()
            ));
            (StatusCode::CREATED, Json(resource)).into_response()
        }
        _ => StatusCode::NO_CONTENT.into_response(),
    }
}

/// A fixture whose environment provisions to a fake SCIM target, on the SCIM page.
fn provisioning() -> Fixture {
    let mut fixture = Fixture::new();
    let address = serve(&fixture, |_| Router::new().fallback(remote));
    let id = fixture.state().selected.clone().expect("an environment");
    fixture
        .store
        .update_environment(
            &id,
            EnvironmentPatch {
                settings: SettingsPatch {
                    scim_enabled: Some(true),
                    scim_base_url: Some(format!("http://{address}")),
                    scim_bearer_token: Some("greendale-scim".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .expect("enable SCIM");
    fixture.wait("SCIM to be enabled", |state| {
        state
            .directory()
            .is_some_and(|directory| directory.environment.settings.scim_enabled)
    });
    fixture.click("nav-SCIM provisioning");
    fixture.wait("the pending changes", |state| {
        !state.scim_refreshing && !state.scim_view.plan.is_empty()
    });
    fixture
}

fn job_done(state: &Workspace) -> bool {
    !state.busy
        && !state.scim_refreshing
        && state.scim_view.job.as_ref().is_some_and(|job| job.done)
}

#[test]
fn sync_runs_a_job_and_the_page_shows_its_outcome() {
    let mut fixture = provisioning();
    let troy = fixture.user_id("tbarnes");
    assert_eq!(fixture.state().scim_view.plan.len(), 13);
    assert!(fixture.has(&format!("change-user-{troy}")));
    assert!(fixture.has("scim-plan"));
    fixture.click("add-entry");
    fixture.wait("the sync", job_done);
    let job = fixture.state().scim_view.job.clone().expect("a job");
    assert!(job.success, "{}", job.message);
    assert_eq!(job.percent, 100);
    assert_eq!(fixture.state().message, job.message);
    assert!(!fixture.state().failed);
    assert_eq!(fixture.text("job-title").as_deref(), Some("Sync completed"));
    assert_eq!(fixture.text("job-message"), Some(job.message.clone()));
    assert!(fixture.state().scim_view.plan.is_empty());
    assert!(fixture.has("scim-plan-empty"));
    assert!(fixture.has("scim-event-0"));
    fixture.click("scim-trace");
    let Some(Editor::History { name, entries, .. }) = &fixture.state().editor else {
        panic!("the trace opens in a history panel");
    };
    assert_eq!(name, "SCIM trace");
    assert!(entries.iter().any(|entry| entry.method == "POST"));
}

#[test]
fn pushing_one_change_leaves_the_others_pending() {
    let mut fixture = provisioning();
    let troy = fixture.user_id("tbarnes");
    fixture.click(&format!("change-user-{troy}/push-resource"));
    fixture.wait("the push", job_done);
    assert!(!fixture.state().failed, "{}", fixture.state().message);
    let job = fixture.state().scim_view.job.clone().expect("a job");
    assert_eq!(
        job.message,
        "sync finished: users 1 created, 0 updated, 0 deleted, 0 failed; groups 0 created, 0 updated, 0 deleted, 0 failed"
    );
    let plan = &fixture.state().scim_view.plan;
    assert_eq!(plan.len(), 13);
    assert!(
        plan.iter()
            .all(|entry| (entry.operation == "create") == (entry.resource_id != troy)),
        "only Troy exists remotely now"
    );
}

#[test]
fn test_connection_and_discovery_report_the_target() {
    let mut fixture = provisioning();
    fixture.click("test");
    fixture.wait("the connection test", |state| !state.busy);
    assert_eq!(fixture.state().message, "SCIM connection succeeded");
    fixture.click("discover");
    fixture.wait("discovery", |state| !state.busy);
    assert_eq!(
        fixture.state().message,
        "SCIM capabilities: PATCH supported; filters supported"
    );
    assert!(!fixture.state().failed);
}

#[test]
fn refresh_defers_while_busy_and_reruns_once_after_an_overlap() {
    let mut fixture = provisioning();
    fixture.rt.update(|state, _| {
        state.busy = true;
        state.refresh_scim();
    });
    assert!(fixture.state().scim_refresh_pending);
    assert!(!fixture.state().scim_refreshing);
    fixture.rt.update(|state, _| {
        state.busy = false;
        state.refresh_scim();
        state.refresh_scim();
    });
    assert!(fixture.state().scim_refreshing);
    assert!(
        fixture.state().scim_refresh_pending,
        "a refresh asked for mid-flight waits for the one running"
    );
    fixture.wait("both refreshes", |state| {
        !state.scim_refreshing && !state.scim_refresh_pending
    });
    assert_eq!(fixture.state().scim_view.plan.len(), 13);
}
