use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use scimtest_core::{Store, api, configuration::SettingsPatch, model::*};
use tower::ServiceExt;

#[tokio::test]
async fn browser_routes_require_local_host_and_same_origin_mutations() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    store
        .create_environment(EnvironmentInput {
            name: "Greendale Portal".into(),
            slug: "greendale".into(),
            settings: SettingsPatch {
                oidc_enabled: Some(true),
                oidc_client_id: Some("study-group".into()),
                oidc_client_secret: Some("greendale-secret".into()),
                ..Default::default()
            },
        })
        .unwrap();
    let app = api::router(store, "greendale-token".into(), "127.0.0.1:18765".into());
    for (method, path) in [
        ("GET", "/inspect/oidc/greendale/playground"),
        ("GET", "/inspect/oidc/greendale/playground/callback"),
        ("GET", "/inspect/oidc/greendale"),
        ("POST", "/inspect/oidc/greendale/playground/refresh"),
        ("POST", "/inspect/oidc/greendale/sessions/end"),
        ("POST", "/inspect/oidc/greendale/revoke"),
    ] {
        for (host, origin) in [
            ("citycollege.example", "http://127.0.0.1:18765"),
            ("127.0.0.1:18765", "https://citycollege.example"),
        ] {
            if method == "GET" && host == "127.0.0.1:18765" {
                continue;
            }
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("Host", host)
                        .header("Origin", origin)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                if host == "citycollege.example" {
                    StatusCode::MISDIRECTED_REQUEST
                } else {
                    StatusCode::FORBIDDEN
                },
                "{method} {path} {host} {origin}"
            );
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
        if method == "GET" {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header("Host", "127.0.0.1:18765")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(response.status().is_success() || response.status().is_redirection());
            assert_eq!(response.headers()["cache-control"], "no-store");
            if path.ends_with("callback") {
                let body = response.into_body().collect().await.unwrap().to_bytes();
                assert!(String::from_utf8_lossy(&body).contains("playground session expired"));
            }
        }
    }
}
