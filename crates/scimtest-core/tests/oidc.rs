#[allow(dead_code)]
mod support;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use http_body_util::BodyExt;
use scimtest_core::{Store, api, configuration::SettingsPatch, model::*};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:19524";
const CALLBACK: &str = "https://greendale.example/callback?from=scimtest";
const TOKEN: &str = "greendale-instance";

#[tokio::test]
async fn identifier_sign_in_and_directory_uniqueness_use_go_unicode_folding() {
    let f = Fixture::new(false, false);
    f.store
        .update_environment(
            &f.id,
            EnvironmentPatch {
                settings: SettingsPatch {
                    chooser_mode: Some("identifier".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    f.store
        .update_user(
            &f.id,
            &f.user,
            UserPatch {
                username: Some("troy-Σ".into()),
                ..Default::default()
            },
        )
        .unwrap();
    let error = f
        .store
        .create_user(
            &f.id,
            UserInput {
                given_name: "Abed".into(),
                email: "abed@greendale.edu".into(),
                username: "TROY-ς".into(),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(error.to_string().contains("already used"));
    let (code, _) = f.code(&[("login_identifier", "troy-ς".into())]).await;
    let (status, tokens) = f.exchange(&code, &[]).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let (_, userinfo) = f.info(tokens["access_token"].as_str().unwrap()).await;
    assert_eq!(userinfo["sub"], f.user);
}
struct Fixture {
    _temporary: tempfile::TempDir,
    store: Store,
    app: Router,
    id: String,
    user: String,
    secret: String,
}
impl Fixture {
    fn new(public: bool, jwt: bool) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("state.db")).unwrap();
        let environment = store
            .create_environment(EnvironmentInput {
                name: "Greendale".into(),
                settings: SettingsPatch {
                    oidc_enabled: Some(true),
                    oidc_public_client: Some(public),
                    oidc_jwt_access_tokens: Some(jwt),
                    oidc_redirect_uris: Some(vec![CALLBACK.into()]),
                    include_groups_claim: Some(true),
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
                    username: "troy".into(),
                    email: "troy@greendale.edu".into(),
                    employee_number: "GCC-42".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        store
            .create_group(
                &environment.id,
                GroupInput {
                    display_name: "Study Group".into(),
                    member_ids: vec![user.id.clone()],
                },
            )
            .unwrap();
        let app = api::router(store.clone(), TOKEN.into(), HOST.into());
        Self {
            _temporary: temporary,
            store,
            app,
            id: environment.id,
            user: user.id,
            secret: environment.settings.oidc_client_secret,
        }
    }
    fn values(&self) -> Vec<(&str, String)> {
        vec![
            ("response_type", "code".into()),
            ("client_id", "greendale".into()),
            ("redirect_uri", CALLBACK.into()),
            ("scope", "openid profile email groups offline_access".into()),
            ("state", "troy & abed".into()),
            ("nonce", "greendale-nonce".into()),
            ("user_id", self.user.clone()),
        ]
    }
    fn credentials(&self) -> Vec<(&str, String)> {
        vec![
            ("client_id", "greendale".into()),
            ("client_secret", self.secret.clone()),
        ]
    }
    async fn code(&self, extra: &[(&str, String)]) -> (String, String) {
        let mut values = self.values();
        values.extend_from_slice(extra);
        let (status, headers, _) = send(
            &self.app,
            "GET",
            &format!("/oidc/greendale/authorize?{}", encode(&values)),
            "",
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::FOUND);
        let location = url::Url::parse(headers["location"].to_str().unwrap()).unwrap();
        let code = location
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned();
        assert_eq!(
            location
                .query_pairs()
                .find(|(key, _)| key == "state")
                .unwrap()
                .1,
            "troy & abed"
        );
        let cookie = headers["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        (code, cookie)
    }
    async fn exchange(&self, code: &str, extra: &[(&str, String)]) -> (StatusCode, Value) {
        let mut values = self.credentials();
        values.extend([
            ("grant_type", "authorization_code".into()),
            ("code", code.into()),
            ("redirect_uri", CALLBACK.into()),
        ]);
        values.extend_from_slice(extra);
        let (status, _, body) = send(
            &self.app,
            "POST",
            "/oidc/greendale/token",
            &encode(&values),
            &[],
        )
        .await;
        (status, parse(&body))
    }
    async fn post(&self, path: &str, values: Vec<(&str, String)>) -> (StatusCode, Value) {
        let (status, _, body) = send(&self.app, "POST", path, &encode(&values), &[]).await;
        (
            status,
            if body.is_empty() {
                Value::Null
            } else {
                parse(&body)
            },
        )
    }
    async fn info(&self, token: &str) -> (StatusCode, Value) {
        let (status, _, body) = send(
            &self.app,
            "GET",
            "/oidc/greendale/userinfo",
            "",
            &[("authorization", format!("Bearer {token}"))],
        )
        .await;
        (status, parse(&body))
    }
    async fn admin(&self, method: &str, suffix: &str) -> (StatusCode, Value) {
        let (status, _, body) = send(
            &self.app,
            method,
            &format!("/api/v1/environments/{}{suffix}", self.id),
            "",
            &[("X-Scimtest-Instance-Token", TOKEN.into())],
        )
        .await;
        (status, parse(&body))
    }
}
fn encode(values: &[(&str, String)]) -> String {
    serde_urlencoded::to_string(values).unwrap()
}
fn parse(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}
fn jwt(token: &Value) -> Value {
    parse(
        &URL_SAFE_NO_PAD
            .decode(token.as_str().unwrap().split('.').nth(1).unwrap())
            .unwrap(),
    )
}
async fn send(
    app: &Router,
    method: &str,
    path: &str,
    body: &str,
    headers: &[(&str, String)],
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", HOST);
    if !body.is_empty() {
        request = request.header("Content-Type", "application/x-www-form-urlencoded");
    }
    for (key, value) in headers {
        request.headers_mut().unwrap().insert(
            axum::http::HeaderName::from_bytes(key.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    let response = app
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

#[tokio::test]
async fn authorization_refresh_and_revocation_work_over_public_http_routes() {
    let f = Fixture::new(false, true);
    let (status, _, body) = send(
        &f.app,
        "GET",
        "/oidc/greendale/.well-known/openid-configuration",
        "",
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let discovery = parse(&body);
    assert_eq!(discovery["issuer"], format!("http://{HOST}/oidc/greendale"));
    assert!(
        discovery["grant_types_supported"]
            .as_array()
            .unwrap()
            .contains(&json!("client_credentials"))
    );
    let (code, cookie) = f.code(&[("authn_strength", "mfa".into())]).await;
    let (status, response) = f.exchange(&code, &[]).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let claims = jwt(&response["id_token"]);
    assert_eq!(claims["sub"], f.user);
    assert_eq!(claims["nonce"], "greendale-nonce");
    assert_eq!(claims["amr"], json!(["pwd", "otp", "mfa"]));
    assert_eq!(claims["employeeNumber"], "GCC-42");
    assert_eq!(claims["groups"], json!(["Study Group"]));
    assert_eq!(claims["acr"], "https://refeds.org/profile/mfa");
    let key = f.store.active_signing_key(&f.id).unwrap();
    let verified = parse(&support::bridge_input(
        "verify-jwt",
        &f._temporary.path().join("state.db"),
        &serde_json::to_vec(
            &json!({"token":response["id_token"],"certificate_pem":key.stored.certificate_pem}),
        )
        .unwrap(),
    ));
    assert_eq!(verified["claims"], claims);
    let (status, _, body) = send(&f.app, "GET", "/oidc/greendale/jwks", "", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(parse(&body)["keys"][0], key.jwk());
    let access = jwt(&response["access_token"]);
    assert_eq!(access["sub"], f.user);
    assert!(access["jti"].is_string());
    let (status, info) = f.info(response["access_token"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(info["name"], "Troy Barnes");
    assert_eq!(f.exchange(&code, &[]).await.1["error"], "invalid_grant");
    let mut values = f.credentials();
    values.extend([
        ("grant_type", "refresh_token".into()),
        (
            "refresh_token",
            response["refresh_token"].as_str().unwrap().into(),
        ),
        ("scope", "openid email".into()),
    ]);
    let (status, narrowed) = f.post("/oidc/greendale/token", values.clone()).await;
    assert_eq!(status, StatusCode::OK, "{narrowed}");
    let narrowed_claims = jwt(&narrowed["id_token"]);
    assert!(narrowed_claims.get("nonce").is_none());
    assert!(narrowed_claims.get("name").is_none());
    assert_eq!(narrowed_claims["auth_time"], claims["auth_time"]);
    assert_eq!(
        f.post("/oidc/greendale/token", values).await.1["error"],
        "invalid_grant"
    );
    let mut values = f.credentials();
    values.extend([
        ("grant_type", "refresh_token".into()),
        (
            "refresh_token",
            narrowed["refresh_token"].as_str().unwrap().into(),
        ),
        ("scope", "openid profile email groups offline_access".into()),
    ]);
    let (status, refreshed) = f.post("/oidc/greendale/token", values).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(jwt(&refreshed["id_token"])["name"], "Troy Barnes");
    let (_, holders) = f.admin("GET", "/oidc/tokens").await;
    assert_eq!(holders["holders"][0]["access_tokens"], 3);
    assert_eq!(holders["holders"][0]["refresh_tokens"], 1);
    let (_, sessions) = f.admin("GET", "/sessions").await;
    assert_eq!(sessions["sessions"][0]["session_id"], claims["sid"]);
    let mut values = f.credentials();
    values.push(("token", refreshed["refresh_token"].as_str().unwrap().into()));
    assert_eq!(
        f.post("/oidc/greendale/revoke", values).await.0,
        StatusCode::OK
    );
    assert_eq!(
        f.info(response["access_token"].as_str().unwrap()).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (_, sessions) = f.admin("GET", "/sessions").await;
    assert_eq!(sessions["sessions"].as_array().unwrap().len(), 1);
    let mut values = f.values();
    values.retain(|(key, _)| *key != "user_id");
    values.push(("prompt", "none".into()));
    let (status, _, _) = send(
        &f.app,
        "GET",
        &format!("/oidc/greendale/authorize?{}", encode(&values)),
        "",
        &[("cookie", cookie)],
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
}

#[tokio::test]
async fn public_clients_require_pkce_and_invalid_attempts_do_not_consume_codes() {
    let f = Fixture::new(true, false);
    let values = f.values();
    let (_, headers, _) = send(
        &f.app,
        "GET",
        &format!("/oidc/greendale/authorize?{}", encode(&values)),
        "",
        &[],
    )
    .await;
    assert!(
        headers["location"]
            .to_str()
            .unwrap()
            .contains("error=invalid_request")
    );
    let verifier = "greendale-community-college-troy-and-abed-morning";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let (code, _) = f
        .code(&[
            ("code_challenge", challenge),
            ("code_challenge_method", "S256".into()),
        ])
        .await;
    assert_eq!(
        f.exchange(&code, &[("code_verifier", "wrong".into())])
            .await
            .1["error"],
        "invalid_grant"
    );
    let (status, response) = f
        .exchange(&code, &[("code_verifier", verifier.into())])
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert!(!response["access_token"].as_str().unwrap().contains('.'));
    assert_eq!(
        f.info(response["access_token"].as_str().unwrap()).await.0,
        StatusCode::OK
    );
    let mut values = f.credentials();
    values.push(("grant_type", "client_credentials".into()));
    assert_eq!(
        f.post("/oidc/greendale/token", values).await.1["error"],
        "unauthorized_client"
    );
}

#[tokio::test]
async fn client_authentication_introspection_and_user_status_are_enforced() {
    let f = Fixture::new(false, false);
    let (code, _) = f.code(&[]).await;
    let values = vec![
        ("grant_type", "authorization_code".into()),
        ("code", code.clone()),
        ("redirect_uri", CALLBACK.into()),
    ];
    let (status, headers, body) = send(
        &f.app,
        "POST",
        "/oidc/greendale/token",
        &encode(&values),
        &[(
            "authorization",
            format!("Basic {}", STANDARD.encode("greendale:wrong")),
        )],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers.contains_key("www-authenticate"));
    assert_eq!(parse(&body)["error"], "invalid_client");
    let credentials = STANDARD.encode(format!("greendale:{}", f.secret));
    let (status, _, body) = send(
        &f.app,
        "POST",
        "/oidc/greendale/token",
        &encode(&values),
        &[("authorization", format!("Basic {credentials}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let response = parse(&body);
    let mut values = f.credentials();
    values.push(("token", response["access_token"].as_str().unwrap().into()));
    assert_eq!(
        f.post("/oidc/greendale/introspect", values.clone()).await.1["active"],
        true
    );
    f.store
        .update_user(
            &f.id,
            &f.user,
            UserPatch {
                active: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        f.post("/oidc/greendale/introspect", values).await.1,
        json!({"active":false})
    );
    assert_eq!(
        f.info(response["access_token"].as_str().unwrap()).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (_, sessions) = f.admin("GET", "/sessions").await;
    assert_eq!(sessions["sessions"], json!([]));
    let mut values = f.credentials();
    values.extend([
        ("grant_type", "client_credentials".into()),
        ("scope", "greendale:read".into()),
    ]);
    let (status, client) = f.post("/oidc/greendale/token", values).await;
    assert_eq!(status, StatusCode::OK);
    assert!(client.get("id_token").is_none());
    assert_eq!(
        f.info(client["access_token"].as_str().unwrap()).await.0,
        StatusCode::UNAUTHORIZED
    );
    let mut values = f.credentials();
    values.push(("token", client["access_token"].as_str().unwrap().into()));
    let (_, active) = f.post("/oidc/greendale/introspect", values).await;
    assert_eq!(active["sub"], "greendale");
    assert_eq!(active["active"], true);
}

#[tokio::test]
async fn unsafe_redirects_and_cross_environment_grants_are_rejected() {
    let f = Fixture::new(false, false);
    for (name, value) in [
        ("redirect_uri", "https://citycollege.example/callback"),
        ("redirect_uri", "javascript:alert(1)"),
        ("client_id", "city-college"),
    ] {
        let mut values = f.values();
        values.retain(|(key, _)| *key != name);
        values.push((name, value.into()));
        let (status, headers, _) = send(
            &f.app,
            "GET",
            &format!("/oidc/greendale/authorize?{}", encode(&values)),
            "",
            &[],
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!headers.contains_key("location"));
    }
    let second = f
        .store
        .create_environment(EnvironmentInput {
            name: "City College".into(),
            settings: SettingsPatch {
                oidc_enabled: Some(true),
                oidc_client_id: Some("city-college".into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
    let (code, _) = f.code(&[]).await;
    let values = vec![
        ("grant_type", "authorization_code".into()),
        ("client_id", "city-college".into()),
        ("client_secret", second.settings.oidc_client_secret.clone()),
        ("code", code.clone()),
        ("redirect_uri", CALLBACK.into()),
    ];
    assert_eq!(
        f.post("/oidc/city-college/token", values).await.1["error"],
        "invalid_grant"
    );
    let (status, token) = f.exchange(&code, &[]).await;
    assert_eq!(status, StatusCode::OK);
    let values = vec![
        ("client_id", "city-college".into()),
        ("client_secret", second.settings.oidc_client_secret),
        ("token", token["access_token"].as_str().unwrap().into()),
    ];
    assert_eq!(
        f.post("/oidc/city-college/introspect", values.clone())
            .await
            .1,
        json!({"active":false})
    );
    assert_eq!(
        f.post("/oidc/city-college/revoke", values).await.0,
        StatusCode::OK
    );
    assert_eq!(
        f.info(token["access_token"].as_str().unwrap()).await.0,
        StatusCode::OK
    );
    let (status, _, _) = send(
        &f.app,
        "GET",
        "/oidc/greendale/jwks",
        "",
        &[("Host", "citycollege.example".into())],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn silent_authentication_and_rp_logout_keep_tokens_separate() {
    let f = Fixture::new(false, false);
    let mut values = f.values();
    values.retain(|(key, _)| *key != "user_id");
    values.push(("prompt", "none".into()));
    let (_, headers, _) = send(
        &f.app,
        "GET",
        &format!("/oidc/greendale/authorize?{}", encode(&values)),
        "",
        &[],
    )
    .await;
    assert!(
        headers["location"]
            .to_str()
            .unwrap()
            .contains("error=login_required")
    );
    let (code, cookie) = f.code(&[]).await;
    let (_, token) = f.exchange(&code, &[]).await;
    let (_, headers, _) = send(
        &f.app,
        "GET",
        &format!("/oidc/greendale/authorize?{}", encode(&values)),
        "",
        &[("cookie", cookie.clone())],
    )
    .await;
    assert!(headers["location"].to_str().unwrap().contains("code="));
    values.push(("max_age", "0".into()));
    let (_, headers, _) = send(
        &f.app,
        "GET",
        &format!("/oidc/greendale/authorize?{}", encode(&values)),
        "",
        &[("cookie", cookie.clone())],
    )
    .await;
    assert!(
        headers["location"]
            .to_str()
            .unwrap()
            .contains("error=login_required")
    );
    let values = vec![
        ("client_id", "greendale".into()),
        ("post_logout_redirect_uri", CALLBACK.into()),
        ("state", "greendale-logout".into()),
    ];
    let (status, _, body) = send(
        &f.app,
        "GET",
        &format!("/oidc/greendale/logout?{}", encode(&values)),
        "",
        &[("cookie", cookie.clone())],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("confirm"));
    let mut values = values;
    values.push(("id_token_hint", token["id_token"].as_str().unwrap().into()));
    let (status, headers, _) = send(
        &f.app,
        "GET",
        &format!("/oidc/greendale/logout?{}", encode(&values)),
        "",
        &[("cookie", cookie)],
    )
    .await;
    assert_eq!(status, StatusCode::FOUND);
    assert!(
        headers["location"]
            .to_str()
            .unwrap()
            .contains("state=greendale-logout")
    );
    assert!(
        headers["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(f.admin("GET", "/sessions").await.1["sessions"], json!([]));
    assert_eq!(
        f.info(token["access_token"].as_str().unwrap()).await.0,
        StatusCode::OK
    );
    let mut values = f.credentials();
    values.push(("token", token["refresh_token"].as_str().unwrap().into()));
    assert_eq!(
        f.post("/oidc/greendale/introspect", values).await.1["active"],
        true
    );
}

#[tokio::test]
async fn personas_claim_mappings_and_entra_group_overage_are_served() {
    let f = Fixture::new(false, false);
    f.store
        .create_group(
            &f.id,
            GroupInput {
                display_name: "Greendale Students".into(),
                member_ids: vec![f.user.clone()],
            },
        )
        .unwrap();
    f.store
        .update_environment(
            &f.id,
            EnvironmentPatch {
                settings: SettingsPatch {
                    persona: Some("entra".into()),
                    groups_overage_threshold: Some(1),
                    oidc_claim_mappings: Some(scimtest_core::configuration::ClaimMappings {
                        email: "upn".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    let (code, _) = f.code(&[]).await;
    let (_, token) = f.exchange(&code, &[]).await;
    let claims = jwt(&token["id_token"]);
    assert_eq!(claims["upn"], "troy@greendale.edu");
    assert!(claims.get("email_verified").is_none());
    assert!(claims.get("groups").is_none());
    assert_eq!(claims["_claim_names"], json!({"groups":"src1"}));
    let endpoint = url::Url::parse(
        claims["_claim_sources"]["src1"]["endpoint"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let request = Request::builder()
        .method("POST")
        .uri(endpoint.path())
        .header("Host", HOST)
        .header(
            "Authorization",
            format!("Bearer {}", token["access_token"].as_str().unwrap()),
        )
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"securityEnabledOnly":true}"#))
        .unwrap();
    let response = f.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = parse(&response.into_body().collect().await.unwrap().to_bytes());
    assert_eq!(body["value"], json!(["Greendale Students", "Study Group"]));
    f.store
        .update_environment(
            &f.id,
            EnvironmentPatch {
                settings: SettingsPatch {
                    persona: Some("okta".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    let (code, _) = f.code(&[]).await;
    let (_, token) = f.exchange(&code, &[]).await;
    let claims = jwt(&token["id_token"]);
    assert_eq!(claims["ver"], 1);
    assert_eq!(claims["groups"][0], "Everyone");
    f.store
        .update_environment(
            &f.id,
            EnvironmentPatch {
                settings: SettingsPatch {
                    persona: Some("google".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    let (code, _) = f.code(&[]).await;
    let (_, token) = f.exchange(&code, &[]).await;
    assert_eq!(jwt(&token["id_token"])["hd"], "greendale.edu");
}

#[tokio::test]
async fn deliberate_faults_affect_only_the_intended_tokens() {
    let f = Fixture::new(false, true);
    let (code, _) = f
        .code(&[
            ("fault_id_token_ttl", "-1m".into()),
            ("fault_drop_claims", "email".into()),
            ("fault_tamper", "nonce_mismatch,wrong_audience".into()),
        ])
        .await;
    let (_, token) = f.exchange(&code, &[]).await;
    let claims = jwt(&token["id_token"]);
    let access = jwt(&token["access_token"]);
    assert!(claims["exp"].as_i64().unwrap() < claims["iat"].as_i64().unwrap());
    assert!(claims.get("email").is_none());
    assert_eq!(claims["nonce"], "greendale-nonce-wrong");
    assert_eq!(claims["aud"], "greendale-wrong");
    assert!(access.get("nonce").is_none());
    assert_eq!(
        access["exp"].as_i64().unwrap() - access["iat"].as_i64().unwrap(),
        3600
    );
    assert!(
        f.info(token["access_token"].as_str().unwrap())
            .await
            .1
            .get("email")
            .is_none()
    );
    let (code, _) = f
        .code(&[("fault_token_error", "temporarily_unavailable".into())])
        .await;
    assert_eq!(
        f.exchange(&code, &[]).await.1["error"],
        "temporarily_unavailable"
    );
    assert_eq!(f.exchange(&code, &[]).await.1["error"], "invalid_grant");
    let (code, _) = f.code(&[("fault_drop_claims", "iat".into())]).await;
    let (_, no_issued_time) = f.exchange(&code, &[]).await;
    assert!(jwt(&no_issued_time["id_token"]).get("iat").is_none());
    let (code, _) = f.code(&[]).await;
    let (first, second) = tokio::join!(f.exchange(&code, &[]), f.exchange(&code, &[]));
    assert!(matches!(
        (first.0, second.0),
        (StatusCode::OK, StatusCode::BAD_REQUEST) | (StatusCode::BAD_REQUEST, StatusCode::OK)
    ));
}

#[tokio::test]
async fn backchannel_logout_posts_a_signed_token() {
    let f = Fixture::new(false, false);
    let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = axum::Router::new().route(
        "/logout",
        axum::routing::post(move |body: axum::body::Bytes| async move {
            sender.send(body.to_vec()).await.unwrap();
            StatusCode::NO_CONTENT
        }),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    f.store
        .update_environment(
            &f.id,
            EnvironmentPatch {
                settings: SettingsPatch {
                    oidc_backchannel_logout_uri: Some(format!("http://{address}/logout")),
                    oidc_backchannel_logout_session_required: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    let (code, _) = f.code(&[]).await;
    let (_, token) = f.exchange(&code, &[]).await;
    let (_, ended) = f.admin("DELETE", "/sessions").await;
    assert_eq!(ended["ended"], 1);
    let body = tokio::time::timeout(std::time::Duration::from_secs(10), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    let form: std::collections::HashMap<String, String> =
        serde_urlencoded::from_bytes(&body).unwrap();
    let key = f.store.active_signing_key(&f.id).unwrap();
    let claims = key.verify_jwt(&form["logout_token"]).unwrap();
    assert_eq!(claims["sub"], f.user);
    assert_eq!(claims["sid"], jwt(&token["id_token"])["sid"]);
    assert_eq!(
        claims["events"],
        json!({"http://schemas.openid.net/event/backchannel-logout":{}})
    );
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        120
    );
    assert_eq!(
        f.info(token["access_token"].as_str().unwrap()).await.0,
        StatusCode::OK
    );
    server.abort();
}

#[tokio::test]
async fn playground_runs_real_http_exchanges_with_a_configured_public_issuer() {
    let temporary = tempfile::tempdir().unwrap();
    let runtime = scimtest_core::runtime::Runtime::start(
        scimtest_core::runtime::Options {
            state_file: Some(temporary.path().join("state.db")),
            port: 0,
            ..Default::default()
        },
        &tokio::runtime::Handle::current(),
    )
    .unwrap();
    let environment = runtime
        .store
        .create_environment(EnvironmentInput {
            name: "Greendale".into(),
            settings: SettingsPatch {
                oidc_enabled: Some(true),
                oidc_public_client: Some(true),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
    let user = runtime
        .store
        .create_user(
            &environment.id,
            UserInput {
                given_name: "Abed".into(),
                family_name: "Nadir".into(),
                email: "abed@greendale.edu".into(),
                ..Default::default()
            },
        )
        .unwrap();
    runtime
        .store
        .update_global_config(&scimtest_core::configuration::GlobalConfigPatch {
            idp_base_url: Some("https://greendale.example".into()),
            ..Default::default()
        })
        .unwrap();
    let result = scimtest_core::oidc::playground(
        runtime.store.clone(),
        environment.id,
        runtime.url.clone(),
        scimtest_core::oidc::PlaygroundInput {
            user_id: user.id,
            refresh: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(result["token_status"], 200, "{result}");
    assert_eq!(result["userinfo_status"], 200);
    assert_eq!(result["refresh_status"], 200);
    assert_eq!(
        result["id_token_claims"]["iss"],
        "https://greendale.example/oidc/greendale"
    );
    assert_eq!(result["userinfo"]["name"], "Abed Nadir");
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn json_authorization_api_and_armed_faults_match_the_protocol_flow() {
    let f = Fixture::new(false, false);
    let path = format!("/api/v1/environments/{}/oidc/authorize", f.id);
    let request=Request::builder().method("POST").uri(path).header("Host",HOST)
        .header("X-Scimtest-Instance-Token",TOKEN).header("Content-Type","application/json")
        .body(Body::from(serde_json::to_vec(&json!({"user_id":f.user,"redirect_uri":CALLBACK,"scope":"openid email","state":"greendale-json","authn_strength":"mfa"})).unwrap())).unwrap();
    let response = f.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("set-cookie"));
    let result = parse(&response.into_body().collect().await.unwrap().to_bytes());
    assert_eq!(result["state"], "greendale-json");
    let (_, token) = f.exchange(result["code"].as_str().unwrap(), &[]).await;
    assert_eq!(jwt(&token["id_token"])["amr"], json!(["pwd", "otp", "mfa"]));
    let path = format!("/api/v1/environments/{}/faults", f.id);
    let request = Request::builder()
        .method("PUT")
        .uri(path)
        .header("Host", HOST)
        .header("X-Scimtest-Instance-Token", TOKEN)
        .header("Content-Type", "application/json")
        .body(Body::from(
            r#"{"tamper":["alg_none","logout_missing_events"]}"#,
        ))
        .unwrap();
    let response = f.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let (code, _) = f.code(&[]).await;
    let (_, token) = f.exchange(&code, &[]).await;
    assert!(token["id_token"].as_str().unwrap().ends_with('.'));
    let (_, armed) = f.admin("GET", "/faults").await;
    assert_eq!(armed["tamper"], json!(["logout_missing_events"]));
    let (code, _) = f.code(&[]).await;
    let (_, token) = f.exchange(&code, &[]).await;
    f.store
        .active_signing_key(&f.id)
        .unwrap()
        .verify_jwt(token["id_token"].as_str().unwrap())
        .unwrap();
}

#[tokio::test]
async fn oauth_basic_credentials_decode_special_characters() {
    let f = Fixture::new(false, false);
    f.store
        .update_environment(
            &f.id,
            EnvironmentPatch {
                settings: SettingsPatch {
                    oidc_client_id: Some("greendale +&@".into()),
                    oidc_client_secret: Some("troy + abed&:morning%".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    let credentials = STANDARD.encode("greendale+%2B%26%40:troy+%2B+abed%26%3Amorning%25");
    let (status, _, body) = send(
        &f.app,
        "POST",
        "/oidc/greendale/token",
        "grant_type=client_credentials",
        &[("authorization", format!("Basic {credentials}"))],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert!(parse(&body)["access_token"].is_string());
}
