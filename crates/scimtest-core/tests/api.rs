use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use scimtest_core::{Store, api, model::*};
use serde_json::{Value, json};
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:18765";
const TOKEN: &str = "greendale-instance-token";

async fn request(app: &Router, method: &str, path: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("Host", HOST)
                .header("X-Scimtest-Instance-Token", TOKEN)
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()["Cache-Control"], "no-store");
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}

#[tokio::test]
async fn api_and_native_store_share_changes_and_patch_preserves_omitted_fields() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    let mut changes = store.subscribe();
    let app = api::router(store.clone(), TOKEN.into(), HOST.into());
    let (status, environment) = request(
        &app,
        "POST",
        "/api/v1/environments",
        json!({"name": "Greendale Portal"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(changes.has_changed().unwrap());
    changes.borrow_and_update();
    let id = environment["id"].as_str().unwrap();
    let users_path = format!("/api/v1/environments/{id}/users");
    let (status, user) = request(&app, "POST", &users_path, json!({"given_name": "Troy", "email": "troy@greendale.edu", "department": "Air Conditioning Repair", "attributes": {"role": "student"}})).await;
    assert_eq!(status, StatusCode::CREATED);
    let user_path = format!("{users_path}/{}", user["id"].as_str().unwrap());
    let (status, updated) = request(
        &app,
        "PATCH",
        &user_path,
        json!({"active": false, "family_name": "Barnes"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["active"], false);
    assert_eq!(updated["given_name"], "Troy");
    assert_eq!(updated["department"], "Air Conditioning Repair");
    assert_eq!(
        store.directory(id).unwrap().users[0].fields.attributes["role"],
        "student"
    );
    let groups_path = format!("/api/v1/environments/{id}/groups");
    let (status, group) = request(
        &app,
        "POST",
        &groups_path,
        json!({"display_name": "Study Group", "member_ids": [user["id"]]}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let group_path = format!("{groups_path}/{}", group["id"].as_str().unwrap());
    let (status, group) = request(&app, "PATCH", &group_path, json!({"member_ids": []})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(group["member_ids"], json!([]));
    let (status, _) = request(&app, "DELETE", &user_path, json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert!(store.directory(id).unwrap().users.is_empty());
}

#[tokio::test]
async fn api_rejects_missing_credentials_wrong_hosts_and_cross_origin_mutations() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    let app = api::router(store, TOKEN.into(), HOST.into());
    let cases = [
        ("no token", HOST, "", None, StatusCode::UNAUTHORIZED),
        (
            "wrong token",
            HOST,
            "city-college-token",
            None,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "wrong host",
            "citycollege.edu",
            TOKEN,
            None,
            StatusCode::MISDIRECTED_REQUEST,
        ),
        (
            "foreign origin",
            HOST,
            TOKEN,
            Some("https://citycollege.edu"),
            StatusCode::FORBIDDEN,
        ),
        (
            "null origin",
            HOST,
            TOKEN,
            Some("null"),
            StatusCode::FORBIDDEN,
        ),
    ];
    for (name, host, token, origin, want) in cases {
        let mut request = Request::builder()
            .method("POST")
            .uri("/api/v1/environments")
            .header("Host", host)
            .header("X-Scimtest-Instance-Token", token)
            .header("Content-Type", "application/json");
        if let Some(origin) = origin {
            request = request.header("Origin", origin);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::from(r#"{"name":"Greendale"}"#)).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), want, "{name}");
        let body: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert!(body["error"].is_string(), "{name}");
    }
    let (status, _) = request(&app, "GET", "/-/ready", json!({})).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/-/ready")
                .header("Host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invalid_fields_and_cross_environment_references_are_rejected_atomically() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    let first = store
        .create_environment(EnvironmentInput {
            name: "Greendale".into(),
            ..Default::default()
        })
        .unwrap();
    let second = store
        .create_environment(EnvironmentInput {
            name: "City College".into(),
            ..Default::default()
        })
        .unwrap();
    let user = store
        .create_user(
            &first.id,
            UserInput {
                given_name: "Troy".into(),
                email: "troy@greendale.edu".into(),
                ..Default::default()
            },
        )
        .unwrap();
    let app = api::router(store.clone(), TOKEN.into(), HOST.into());
    let path = format!("/api/v1/environments/{}/users/{}", first.id, user.id);
    for body in [
        json!({"active": null}),
        json!({"active": "false"}),
        json!({"remote_id": "forged"}),
        json!([]),
    ] {
        let (status, error) = request(&app, "PATCH", &path, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(error["error"].is_string());
    }
    assert!(store.directory(&first.id).unwrap().users[0].fields.active);
    let (status, _) = request(
        &app,
        "GET",
        &format!("/api/v1/environments/{}/users/{}", second.id, user.id),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = request(
        &app,
        "POST",
        &format!("/api/v1/environments/{}/groups", second.id),
        json!({"display_name": "Study Group", "member_ids": [user.id]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(store.directory(&second.id).unwrap().groups.is_empty());
}

#[tokio::test]
async fn environment_settings_preserve_secrets_and_reject_read_only_or_null_fields() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    let app = api::router(store.clone(), TOKEN.into(), HOST.into());
    let (status, environment) = request(&app, "POST", "/api/v1/environments", json!({
        "name": "Greendale", "oidc_enabled": true, "oidc_redirect_uris": [" https://greendale.example/callback?source=oidc "],
        "saml_enabled": true, "saml_entity_id": "urn:greendale:sp", "saml_acs_url": "https://greendale.example/acs?source=saml",
        "saml_name_id_field": "firstName", "chooser_mode": "identifier", "scim_enabled": true, "scim_base_url": "https://greendale.example/scim"
    })).await;
    assert_eq!(status, StatusCode::CREATED, "{environment}");
    assert_eq!(environment["protocol"], "both");
    assert_eq!(environment["oidc_client_id"], "greendale");
    assert_eq!(
        environment["saml_name_id_format"],
        "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
    );
    assert!(environment.get("scim_enabled").is_none());
    let path = format!(
        "/api/v1/environments/{}",
        environment["id"].as_str().unwrap()
    );
    let secret = environment["oidc_client_secret"].clone();
    assert_eq!(secret.as_str().unwrap().len(), 32);
    for body in [
        json!({"scim_capabilities_known": true}),
        json!({"scim_patch_supported": true}),
        json!({"saml_name_id_format": "forged"}),
        json!({"protocol": "both"}),
        json!({"oidc_claim_mappings": {"name": null}}),
        json!({"saml_attribute_mappings": {"unknown": "value"}}),
    ] {
        let (status, body) = request(&app, "PATCH", &path, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
    let (status, updated) = request(
        &app,
        "PATCH",
        &path,
        json!({"oidc_client_secret": "", "scim_bearer_token": " greendale-token "}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["oidc_client_secret"], secret);
    assert_eq!(updated["scim_enabled"], true);
    let (status, updated) = request(
        &app,
        "PATCH",
        &path,
        json!({"regenerate_oidc_secret": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(updated["oidc_client_secret"], secret);
    let (status, updated) =
        request(&app, "PATCH", &path, json!({"oidc_public_client": true})).await;
    assert_eq!(status, StatusCode::OK);
    assert!(updated.get("oidc_client_secret").is_none());
    let (status, _) = request(
        &app,
        "POST",
        "/api/v1/environments",
        json!({"name": "City College", "oidc_enabled": true, "oidc_client_id": "greendale"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    for body in [
        json!({"scim_base_url": "https://greendale.example/scim?query=unsafe"}),
        json!({"saml_request_certificate_pem": "invalid certificate"}),
        json!({"oidc_redirect_uris": ["greendale:/callback"]}),
    ] {
        let (status, _) = request(&app, "PATCH", &path, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn bulk_deletion_history_and_restore_follow_remembered_scim_state() {
    let temporary = tempfile::tempdir().unwrap();
    let database_path = temporary.path().join("state.db");
    let store = Store::open(&database_path).unwrap();
    let app = api::router(store.clone(), TOKEN.into(), HOST.into());
    let (_, environment) = request(&app, "POST", "/api/v1/environments", json!({"name": "Greendale", "scim_enabled": true, "scim_base_url": "https://greendale.example/scim", "scim_bearer_token": "greendale-token"})).await;
    let base = format!(
        "/api/v1/environments/{}",
        environment["id"].as_str().unwrap()
    );
    let (_, user) = request(
        &app,
        "POST",
        &format!("{base}/users"),
        json!({"given_name": "Troy", "email": "troy@greendale.edu"}),
    )
    .await;
    let user_path = format!("{base}/users/{}", user["id"].as_str().unwrap());
    let (_, group) = request(
        &app,
        "POST",
        &format!("{base}/groups"),
        json!({"display_name": "Study Group", "member_ids": [user["id"], user["id"]]}),
    )
    .await;
    assert_eq!(group["member_ids"].as_array().unwrap().len(), 1);
    let database = rusqlite::Connection::open(&database_path).unwrap();
    database
        .execute(
            "UPDATE app_user_sync SET remote_id = 'remote_troy', dirty = 0",
            [],
        )
        .unwrap();
    let (status, _) = request(
        &app,
        "POST",
        &format!("{base}/users/bulk-delete"),
        json!({"ids": [user["id"], "missing"]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        !store
            .directory(environment["id"].as_str().unwrap())
            .unwrap()
            .users[0]
            .deleted
    );
    let (status, _) = request(&app, "PATCH", &base, json!({"scim_enabled": false})).await;
    assert_eq!(status, StatusCode::OK);
    let (status, result) = request(&app, "DELETE", &user_path, json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["message"], "user marked for deletion");
    let directory = store
        .directory(environment["id"].as_str().unwrap())
        .unwrap();
    let sync = &directory.user_sync[user["id"].as_str().unwrap()];
    assert_eq!(sync.remote_id, "remote_troy");
    assert!(sync.deleted && sync.dirty);
    let (status, _) = request(&app, "PATCH", &user_path, json!({"active": false})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, restored) =
        request(&app, "POST", &format!("{user_path}/restore"), json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(restored["deleted"], false);
    let (status, _) = request(&app, "PATCH", &base, json!({"scim_enabled": true, "scim_base_url": "https://greendale.example/scim", "scim_bearer_token": "greendale-token"})).await;
    assert_eq!(status, StatusCode::OK);
    let (_, projected) = request(&app, "GET", &user_path, json!({})).await;
    assert!(projected.get("remote_id").is_none());
    assert_eq!(projected["dirty"], true);
    let (_, operations) = request(&app, "GET", &format!("{user_path}/operations"), json!({})).await;
    assert_eq!(operations[0]["Summary"], "Restored");
    assert_eq!(operations[1]["Summary"], "Marked for deletion");
    assert_eq!(operations[2]["Summary"], "Created");
}

#[tokio::test]
async fn backups_restore_one_environment_and_keep_private_installation_data() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("state.db");
    let store = Store::open(&path).unwrap();
    let app = api::router(store.clone(), TOKEN.into(), HOST.into());
    let (_, first) = request(
        &app,
        "POST",
        "/api/v1/environments",
        json!({"name": "Greendale"}),
    )
    .await;
    let (_, second) = request(
        &app,
        "POST",
        "/api/v1/environments",
        json!({"name": "City College"}),
    )
    .await;
    let base = format!("/api/v1/environments/{}", first["id"].as_str().unwrap());
    let (_, user) = request(
        &app,
        "POST",
        &format!("{base}/users"),
        json!({"given_name": "Troy", "email": "troy@greendale.edu"}),
    )
    .await;
    let (_, backup) = request(&app, "GET", &format!("{base}/backup"), json!({})).await;
    let database = rusqlite::Connection::open(&path).unwrap();
    database
        .execute(
            "INSERT INTO config VALUES ('installation_private_key', 'greendale-private-key')",
            [],
        )
        .unwrap();
    let (status, _) = request(
        &app,
        "DELETE",
        &format!("{base}/users/{}", user["id"].as_str().unwrap()),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, restored) =
        request(&app, "POST", &format!("{base}/restore"), backup.clone()).await;
    assert_eq!(status, StatusCode::OK, "{restored}");
    assert!(std::path::Path::new(restored["safety_backup"].as_str().unwrap()).exists());
    assert_eq!(
        store
            .directory(first["id"].as_str().unwrap())
            .unwrap()
            .users
            .len(),
        1
    );
    assert!(
        store
            .directory(second["id"].as_str().unwrap())
            .unwrap()
            .users
            .is_empty()
    );
    assert_eq!(
        database
            .query_row(
                "SELECT value FROM config WHERE key = 'installation_private_key'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "greendale-private-key"
    );
    let (status, _) = request(
        &app,
        "POST",
        &format!(
            "/api/v1/environments/{}/restore",
            second["id"].as_str().unwrap()
        ),
        backup,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = request(
        &app,
        "DELETE",
        &format!("{base}/users/{}", user["id"].as_str().unwrap()),
        json!({"unexpected": true}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn recording_settings_and_directory_tools_follow_the_api_contract() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    let app = api::router(store, TOKEN.into(), HOST.into());
    let (status, config) = request(&app, "PATCH", "/api/v1/config", json!({"record_traffic": true, "record_secrets": true, "idp_base_url": "https://greendale.example/"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(config["record_secrets"], true);
    let (_, config) = request(
        &app,
        "PATCH",
        "/api/v1/config",
        json!({"record_traffic": false}),
    )
    .await;
    assert_eq!(config["record_secrets"], false);
    assert_eq!(config["idp_base_url"], "https://greendale.example");
    let (_, environment) = request(
        &app,
        "POST",
        "/api/v1/environments",
        json!({"name": "Greendale"}),
    )
    .await;
    let base = format!(
        "/api/v1/environments/{}",
        environment["id"].as_str().unwrap()
    );
    let (status, created) = request(
        &app,
        "POST",
        &format!("{base}/tools/create-users"),
        json!({"count": 3}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(created["users_changed"], 3);
    let (_, deactivated) = request(
        &app,
        "POST",
        &format!("{base}/tools/deactivate-all"),
        json!({}),
    )
    .await;
    assert_eq!(deactivated["users_changed"], 3);
    let (_, deactivated) = request(
        &app,
        "POST",
        &format!("{base}/tools/deactivate-all"),
        json!({}),
    )
    .await;
    assert_eq!(deactivated["users_changed"], 0);
    let (_, deleted) = request(&app, "POST", &format!("{base}/tools/delete-all"), json!({})).await;
    assert_eq!(deleted["users_changed"], 3);
    let (_, users) = request(&app, "GET", &format!("{base}/users"), json!({})).await;
    assert_eq!(users, json!([]));
    let (_, catalog) = request(&app, "GET", "/api/v1", json!({})).await;
    assert_eq!(catalog["version"], "v1");
    assert!(
        catalog["routes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|route| route["path"]
                == "/api/v1/environments/{environment_id}/signing-keys/rotate")
    );
}
