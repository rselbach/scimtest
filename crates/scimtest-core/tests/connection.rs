use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode},
};
use chrono::Duration;
use http_body_util::BodyExt;
use scimtest_core::{
    Store, api,
    configuration::{GlobalConfigPatch, SettingsPatch},
    model::*,
    signing::CertificateValidity,
};
use serde_json::{Value, json};
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:19527";
const TOKEN: &str = "greendale-instance";
fn environment(store: &Store) -> Environment {
    store
        .create_environment(EnvironmentInput {
            name: "Greendale".into(),
            settings: SettingsPatch {
                oidc_enabled: Some(true),
                oidc_client_id: Some("greendale-portal".into()),
                oidc_redirect_uris: Some(vec!["https://greendale.example/callback".into()]),
                saml_enabled: Some(true),
                saml_acs_url: Some("https://greendale.example/acs".into()),
                saml_entity_id: Some("urn:greendale:sp".into()),
                saml_slo_url: Some("https://greendale.example/slo".into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap()
}
async fn get(app: Router, path: &str, host: &str, token: bool) -> (StatusCode, HeaderMap, Value) {
    let mut request = Request::builder()
        .uri(path)
        .header("Host", host)
        .header("X-Forwarded-Proto", "https, http");
    if token {
        request = request.header("X-Scimtest-Instance-Token", TOKEN);
    }
    let response = app
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    (status, headers, body)
}

#[tokio::test]
async fn browser_download_and_authenticated_api_export_the_same_connection_values() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    let environment = environment(&store);
    let app = api::router(store.clone(), TOKEN.into(), HOST.into());
    let path = format!("/apps/{}/config.json", environment.id);
    let (status, headers, browser) = get(app.clone(), &path, HOST, false).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "no-store");
    let (status, _, api) = get(
        app.clone(),
        &format!("/api/v1/environments/{}/connection", environment.id),
        HOST,
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(browser, api);
    assert_eq!(
        api,
        store
            .connection_config(&environment.id, &format!("http://{HOST}"))
            .unwrap()
    );
    let oidc = &api["oidc"];
    assert_eq!(oidc["issuer"], format!("http://{HOST}/oidc/greendale"));
    assert_eq!(
        oidc["client_secret"],
        environment.settings.oidc_client_secret
    );
    assert_eq!(
        oidc["redirect_uris"],
        json!(["https://greendale.example/callback"])
    );
    assert_eq!(oidc["public_client"], false);
    assert_eq!(oidc["jwt_access_tokens"], false);
    assert!(oidc.get("access_token_audience").is_none());
    for (field, suffix) in [
        ("discovery_url", "/.well-known/openid-configuration"),
        ("authorize_url", "/authorize"),
        ("token_url", "/token"),
        ("userinfo_url", "/userinfo"),
        ("jwks_url", "/jwks"),
        ("introspection_url", "/introspect"),
        ("revocation_url", "/revoke"),
    ] {
        assert_eq!(
            oidc[field],
            format!("{}{suffix}", oidc["issuer"].as_str().unwrap())
        );
    }
    assert_eq!(
        api["saml"]["sso_url"],
        format!("http://{HOST}/saml/greendale/sso")
    );
    assert_eq!(api["saml"]["metadata_url"], api["saml"]["idp_entity_id"]);
    assert_eq!(
        api["saml"]["name_id_format"],
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    );
    assert_eq!(api["saml"]["sp_slo_url"], "https://greendale.example/slo");
    assert_eq!(
        get(app.clone(), &path, "citycollege.example", false)
            .await
            .0,
        StatusCode::MISDIRECTED_REQUEST
    );
    assert_eq!(
        get(app.clone(), "/apps/missing/config.json", HOST, false)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(
            app,
            &format!("/api/v1/environments/{}/connection", environment.id),
            HOST,
            false
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn public_clients_jwt_audiences_and_configured_origins_follow_go_omission_rules() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    let environment = environment(&store);
    store
        .update_environment(
            &environment.id,
            EnvironmentPatch {
                settings: SettingsPatch {
                    oidc_public_client: Some(true),
                    oidc_jwt_access_tokens: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    let app = api::router(store.clone(), TOKEN.into(), HOST.into());
    let path = format!("/apps/{}/config.json", environment.id);
    let (_, _, config) = get(app.clone(), &path, HOST, false).await;
    assert!(config["oidc"].get("client_secret").is_none());
    assert_eq!(config["oidc"]["access_token_audience"], "greendale-portal");
    store
        .update_global_config(&GlobalConfigPatch {
            trust_forwarded_headers: Some(true),
            ..Default::default()
        })
        .unwrap();
    let (_, _, config) = get(app.clone(), &path, HOST, false).await;
    assert_eq!(
        config["oidc"]["issuer"],
        format!("https://{HOST}/oidc/greendale")
    );
    store
        .update_global_config(&GlobalConfigPatch {
            idp_base_url: Some("https://identity.greendale.example/prefix/".into()),
            ..Default::default()
        })
        .unwrap();
    store
        .update_environment(
            &environment.id,
            EnvironmentPatch {
                settings: SettingsPatch {
                    oidc_access_token_audience: Some("greendale-api".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    let (_, _, config) = get(app, &path, HOST, false).await;
    assert_eq!(
        config["oidc"]["issuer"],
        "https://identity.greendale.example/prefix/oidc/greendale"
    );
    assert_eq!(config["oidc"]["access_token_audience"], "greendale-api");
    let none = store
        .create_environment(EnvironmentInput {
            name: "City College".into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        store
            .connection_config(&none.id, "http://localhost")
            .unwrap(),
        json!({"environment":"City College","slug":"city-college"})
    );
}

#[test]
fn saved_config_uses_private_permissions_and_the_current_signing_certificate() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    let environment = environment(&store);
    let destination = temporary.path().join("greendale-config.json");
    let before = store
        .connection_config(&environment.id, "https://identity.greendale.example")
        .unwrap();
    store
        .write_connection_config(
            &environment.id,
            "https://identity.greendale.example",
            &destination,
        )
        .unwrap();
    let config: Value = serde_json::from_slice(&std::fs::read(&destination).unwrap()).unwrap();
    assert_eq!(config, before);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&destination)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    store
        .rotate_signing_key(
            &environment.id,
            Duration::hours(1),
            CertificateValidity::Standard,
        )
        .unwrap();
    store
        .write_connection_config(
            &environment.id,
            "https://identity.greendale.example",
            &destination,
        )
        .unwrap();
    let after: Value = serde_json::from_slice(&std::fs::read(&destination).unwrap()).unwrap();
    assert_ne!(
        after["saml"]["certificate_pem"],
        before["saml"]["certificate_pem"]
    );
    let directory = temporary.path().join("cannot-replace-directory");
    std::fs::create_dir(&directory).unwrap();
    assert!(
        store
            .write_connection_config(
                &environment.id,
                "https://identity.greendale.example",
                &directory
            )
            .is_err()
    );
    assert!(!std::fs::read_dir(temporary.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".scimtest-config-")
    }));
}
