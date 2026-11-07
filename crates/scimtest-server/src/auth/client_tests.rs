use super::*;
use scimtest_core::{
    Store as DesktopStore,
    tunnel::{Config as TunnelConfig, Service, Snapshot},
};

async fn wait(service: &Service, predicate: impl Fn(&Snapshot) -> bool) -> Snapshot {
    let mut changes = service.subscribe();
    tokio::time::timeout(StdDuration::from_secs(10), async {
        loop {
            let snapshot = service.snapshot().unwrap();
            if predicate(&snapshot) {
                return snapshot;
            }
            changes.changed().await.unwrap();
        }
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_rust_client_enrolls_recovers_switches_accounts_and_restarts_with_a_stable_identity()
{
    let mut app = Running::configured(false, 5, true).await;
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = local.local_addr().unwrap().port();
    let local_app = Router::new().fallback(|request: Request| async move {
        axum::Json(
            json!({"forwarded_path":request.uri().path(),"host":header(request.headers(),"host")}),
        )
    });
    let local_shutdown = CancellationToken::new();
    let local_stop = local_shutdown.clone();
    let local_task = tokio::spawn(async move {
        axum::serve(local, local_app)
            .with_graceful_shutdown(local_stop.cancelled_owned())
            .await
            .unwrap();
    });
    let desktop_path = app.directory.path().join("desktop.db");
    let store = DesktopStore::open(&desktop_path).unwrap();
    let config = TunnelConfig {
        server_base_url: app.base.clone(),
        application_profile_id: app.profile.clone(),
        require_account: true,
    };
    let service = Service::new(store.clone(), Some(config.clone()), port).unwrap();
    service.start().unwrap();
    let authorizing = wait(&service, |snapshot| snapshot.state() == "authorizing").await;
    assert!(!service.unlocked().unwrap());
    assert!(!authorizing.enrollment_code.is_empty());
    let response = app
        .approve(&Message {
            enrollment_browser_handoff_url: service.authorization_url().unwrap(),
            ..Default::default()
        })
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let connected = wait(&service, |snapshot| snapshot.connected).await;
    let first_url = connected.public_url.unwrap();
    let first_id = store.installation_identity().unwrap().fingerprint();
    assert!(service.unlocked().unwrap());
    assert_eq!(service.account().unwrap()["login"], "troy-barnes");
    let response = app
        .client
        .get(format!("{first_url}/oidc/greendale/jwks"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.json::<Value>().await.unwrap()["forwarded_path"],
        format!(
            "{}/oidc/greendale/jwks",
            Url::parse(&first_url).unwrap().path()
        )
    );
    app.server
        .store()
        .set_instance_revoked(&app.profile, &first_id, true)
        .unwrap();
    app.server.0.disconnect_instance(&app.profile, &first_id);
    wait(&service, |snapshot| snapshot.retry_available).await;
    assert!(!service.unlocked().unwrap());
    app.server
        .store()
        .set_instance_revoked(&app.profile, &first_id, false)
        .unwrap();
    service.retry().unwrap();
    let recovered = wait(&service, |snapshot| snapshot.connected).await;
    assert_eq!(recovered.public_url.as_deref(), Some(first_url.as_str()));
    *lock(&app.stub.user) = GitHubUser {
        id: 202,
        login: "abed-nadir".into(),
    };
    service.logout().await.unwrap();
    wait(&service, |snapshot| snapshot.state() == "authorizing").await;
    assert!(!service.unlocked().unwrap());
    let second_id = store.installation_identity().unwrap().fingerprint();
    assert_ne!(second_id, first_id);
    assert_eq!(
        app.approve(&Message {
            enrollment_browser_handoff_url: service.authorization_url().unwrap(),
            ..Default::default()
        })
        .await
        .status(),
        StatusCode::OK
    );
    let switched = wait(&service, |snapshot| snapshot.connected).await;
    assert_eq!(service.account().unwrap()["login"], "abed-nadir");
    let second_url = switched.public_url.unwrap();
    assert_ne!(first_url, second_url);
    service.shutdown().await.unwrap();
    app.wait_disconnected().await;
    let reopened = DesktopStore::open(&desktop_path).unwrap();
    assert_eq!(
        reopened.installation_identity().unwrap().fingerprint(),
        second_id
    );
    let restarted = Service::new(reopened, Some(config), port).unwrap();
    restarted.start().unwrap();
    let restored = wait(&restarted, |snapshot| snapshot.connected).await;
    assert_eq!(restored.public_url.as_deref(), Some(second_url.as_str()));
    assert_eq!(restarted.account().unwrap()["login"], "abed-nadir");
    restarted.shutdown().await.unwrap();
    app.wait_disconnected().await;
    local_shutdown.cancel();
    local_task.await.unwrap();
    app.stop().await;
}
