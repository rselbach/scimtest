use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use scimtest_core::{Store, api, configuration::SettingsPatch, model::*};
use serde_json::{Value, json};
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:19525";
struct Fixture {
    _temporary: tempfile::TempDir,
    app: Router,
    secret: String,
    user: String,
}
impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("state.db")).unwrap();
        let environment = store
            .create_environment(EnvironmentInput {
                name: "Greendale".into(),
                settings: SettingsPatch {
                    oidc_enabled: Some(true),
                    oidc_client_id: Some("greendale".into()),
                    oidc_jwt_access_tokens: Some(true),
                    saml_enabled: Some(true),
                    saml_entity_id: Some("urn:greendale:sp".into()),
                    saml_acs_url: Some("https://greendale.example/acs".into()),
                    ..Default::default()
                },
                ..Default::default()
            })
            .unwrap();
        let user = store
            .create_user(
                &environment.id,
                UserInput {
                    given_name: "Troy".into(),
                    family_name: "Barnes".into(),
                    email: "troy@greendale.edu".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        Self {
            _temporary: temporary,
            app: api::router(store, "greendale-instance".into(), HOST.into()),
            secret: environment.settings.oidc_client_secret,
            user: user.id,
        }
    }
    async fn send(
        &self,
        method: &str,
        path: &str,
        body: &str,
        extra: &[(&str, &str)],
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("Host", HOST);
        if path.starts_with("/api/") {
            request = request
                .header("X-Scimtest-Instance-Token", "greendale-instance")
                .header("Content-Type", "application/json");
        } else if !body.is_empty() {
            request = request.header("Content-Type", "application/x-www-form-urlencoded");
        }
        for (name, value) in extra {
            request = request.header(*name, *value);
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        (status, headers, bytes)
    }
    async fn admin(&self, method: &str, path: &str, body: Value) -> Value {
        let (status, _, bytes) = self.send(method, path, &body.to_string(), &[]).await;
        assert!(
            status.is_success(),
            "{}: {}",
            status,
            String::from_utf8_lossy(&bytes)
        );
        if bytes.is_empty() {
            return Value::Null;
        }
        serde_json::from_slice(&bytes).unwrap()
    }
    async fn traffic(&self) -> Value {
        self.admin("GET", "/api/v1/traffic", json!({})).await
    }
    async fn settings(&self, value: Value) -> Value {
        self.admin("PATCH", "/api/v1/traffic/settings", value).await
    }
}

#[tokio::test]
async fn malformed_json_is_omitted_until_secret_recording_is_explicitly_enabled() {
    let f = Fixture::new();
    let malformed =
        r#"{"access_token":"greendale-private-token","nested":{"client_secret":"troy-secret""#;
    for secrets in [false, true] {
        f.settings(json!({"record":true,"record_secrets":secrets}))
            .await;
        let response = f
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oidc/greendale/token")
                    .header("Host", HOST)
                    .header("Content-Type", "application/json")
                    .body(Body::from(malformed))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let traffic = f.traffic().await;
        let text = traffic["entries"][0].as_str().unwrap();
        assert_eq!(text.contains("greendale-private-token"), secrets);
        assert_eq!(text.contains("troy-secret"), secrets);
        assert_eq!(text.contains("malformed JSON omitted"), !secrets);
    }
}

#[tokio::test]
async fn traffic_controls_redact_credentials_without_changing_protocol_responses() {
    let f = Fixture::new();
    let path = "/oidc/greendale/.well-known/openid-configuration";
    assert_eq!(f.send("GET", path, "", &[]).await.0, StatusCode::OK);
    assert_eq!(f.traffic().await["entries"], json!([]));
    let settings = f.settings(json!({"record_secrets":true})).await;
    assert_eq!(settings["record"], false);
    assert_eq!(settings["record_secrets"], false);
    f.admin("PATCH", "/api/v1/config", json!({"record_traffic":true}))
        .await;
    let (status, _, body) = f
        .send(
            "GET",
            &format!("{path}?code=greendale-code&id_token_hint=greendale-hint"),
            "",
            &[
                ("Authorization", "Bearer greendale-credential"),
                ("Cookie", "greendale-session=private-cookie"),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let discovery: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(discovery["issuer"], format!("http://{HOST}/oidc/greendale"));
    let traffic = f.traffic().await;
    let text = traffic["entries"][0].as_str().unwrap();
    for secret in [
        "greendale-code",
        "greendale-hint",
        "greendale-credential",
        "private-cookie",
    ] {
        assert!(!text.contains(secret), "{secret}: {text}");
    }
    assert!(text.contains("[REDACTED]"));
    let form = serde_urlencoded::to_string([
        ("grant_type", "client_credentials"),
        ("client_id", "greendale"),
        ("client_secret", &f.secret),
    ])
    .unwrap();
    let (status, _, bytes) = f.send("POST", "/oidc/greendale/token", &form, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let token: Value = serde_json::from_slice(&bytes).unwrap();
    let access = token["access_token"].as_str().unwrap();
    let traffic = f.traffic().await;
    let text = traffic["entries"][0].as_str().unwrap();
    assert!(!text.contains(&f.secret));
    assert!(!text.contains(access));
    assert!(text.contains("client_credentials"));
    f.settings(json!({"record_secrets":true})).await;
    let (_, _, bytes) = f.send("POST", "/oidc/greendale/token", &form, &[]).await;
    let token: Value = serde_json::from_slice(&bytes).unwrap();
    let traffic = f.traffic().await;
    let text = traffic["entries"][0].as_str().unwrap();
    assert!(text.contains(&f.secret));
    assert!(text.contains(token["access_token"].as_str().unwrap()));
    assert!(text.contains("decoded access_token"));
    let count = traffic["entries"].as_array().unwrap().len();
    let settings = f.settings(json!({"record":false})).await;
    assert_eq!(settings["record_secrets"], false);
    f.send("GET", path, "", &[]).await;
    assert_eq!(
        f.traffic().await["entries"].as_array().unwrap().len(),
        count
    );
    let (status, _, bytes) = f.send("DELETE", "/api/v1/traffic", "", &[]).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(bytes.is_empty());
    assert_eq!(f.traffic().await["entries"], json!([]));
}

#[tokio::test]
async fn saml_requests_are_decoded_and_responses_and_session_cookies_require_secrets() {
    let f = Fixture::new();
    f.settings(json!({"record":true})).await;
    let xml = format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_study-group" Destination="http://{HOST}/saml/greendale/sso"><saml:Issuer>urn:greendale:sp</saml:Issuer></samlp:AuthnRequest>"#
    );
    let form = serde_urlencoded::to_string([
        ("user_id", f.user.clone()),
        ("SAMLRequest", STANDARD.encode(xml)),
    ])
    .unwrap();
    let (status, headers, bytes) = f.send("POST", "/saml/greendale/sso", &form, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8(bytes).unwrap();
    let encoded = html
        .split("name=\"SAMLResponse\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let cookie = headers["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let traffic = f.traffic().await;
    let text = traffic["entries"][0].as_str().unwrap();
    assert!(text.contains("decoded SAMLRequest"));
    assert!(text.contains("_study-group"));
    assert!(!text.contains(encoded));
    assert!(!text.contains(cookie));
    assert!(!text.contains("troy@greendale.edu"));
    f.settings(json!({"record_secrets":true})).await;
    let (status, _, _) = f.send("POST", "/saml/greendale/sso", &form, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let traffic = f.traffic().await;
    let text = traffic["entries"][0].as_str().unwrap();
    assert!(text.contains("decoded SAMLResponse"));
    assert!(text.contains("troy@greendale.edu"));
    assert!(text.contains("<saml:Assertion"));
}

#[tokio::test]
async fn traffic_retains_the_latest_hundred_exchanges_and_discovery_alias_works() {
    let f = Fixture::new();
    f.settings(json!({"record":true})).await;
    for sequence in 0..125 {
        let (status, _, body) = f
            .send(
                "GET",
                &format!("/.well-known/openid-configuration/oidc/greendale?sequence={sequence}"),
                "",
                &[],
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    }
    let traffic = f.traffic().await;
    let entries = traffic["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 100);
    assert!(entries[0].as_str().unwrap().contains("sequence=124"));
    assert!(entries[99].as_str().unwrap().contains("sequence=25"));
}
