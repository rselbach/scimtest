use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use scimtest_core::{
    Store, api, configuration::SettingsPatch, model::EnvironmentInput, oidc::Identity,
};
use serde_json::{Value, json};
use tower::ServiceExt;

#[tokio::test]
async fn fault_api_normalizes_values_and_rejects_invalid_input_without_replacing_armed_faults() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    let environment = store
        .create_environment(EnvironmentInput {
            name: "Greendale".into(),
            settings: SettingsPatch {
                oidc_enabled: Some(true),
                oidc_redirect_uris: Some(vec!["https://greendale.example/callback".into()]),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
    let identity = Identity::new(store.clone());
    let app = api::router_with_identity(
        store,
        "greendale-instance".into(),
        "127.0.0.1:19526".into(),
        identity.clone(),
    );
    let path = format!("/api/v1/environments/{}/faults", environment.id);
    let put = |body: Value| {
        let app = app.clone();
        let path = path.clone();
        async move {
            let response = app
                .oneshot(
                    Request::builder()
                        .method("PUT")
                        .uri(path)
                        .header("Host", "127.0.0.1:19526")
                        .header("X-Scimtest-Instance-Token", "greendale-instance")
                        .header("Content-Type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body: Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            (status, body)
        }
    };
    let (status, value) = put(json!({"id_token_ttl":" -1m ","assertion_ttl":" ","clock_skew":" 0 ","drop_claims":[" email, name ","","email"],"token_error":" temporarily_unavailable ","saml_status":" responder ","tamper":[" wrong_audience,logout_missing_events ","wrong_audience", ""]})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        value,
        json!({"active":true,"id_token_ttl":"-1m0s","id_token_ttl_set":true,"assertion_ttl":"0s","assertion_ttl_set":false,"clock_skew":"0s","break_signature":false,"drop_claims":["email","name","email"],"token_error":"temporarily_unavailable","saml_status":"urn:oasis:names:tc:SAML:2.0:status:Responder","tamper":["wrong_audience","logout_missing_events"]})
    );
    for invalid in [
        json!({"clock_skew":"0s"}),
        json!({"id_token_ttl":""}),
        json!({"id_token_ttl":"yesterday"}),
        json!({"tamper":["unknown"]}),
        json!({"saml_status":"urn:oasis:names:tc:SAML:2.0:status:Responder"}),
    ] {
        assert_eq!(put(invalid).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            identity.faults(&environment.id).unwrap().token_error,
            "temporarily_unavailable"
        );
    }
    assert_eq!(
        put(json!({"id_token_ttl":"0s","tamper":null})).await.0,
        StatusCode::BAD_REQUEST
    );
    let (status, value) = put(json!({"id_token_ttl":"0s"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["id_token_ttl_set"], true);
    assert_eq!(value["active"], true);
    assert!(value["tamper"].is_null());
}
