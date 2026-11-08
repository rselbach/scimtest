use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use http_body_util::BodyExt;
use scimtest_core::{
    Store, api,
    configuration::SettingsPatch,
    model::*,
    oidc::{Faults, Identity},
};
use serde_json::{Value, json};
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:19526";
const CALLBACK: &str = "https://greendale.example/callback";
struct Fixture {
    _temporary: tempfile::TempDir,
    store: Store,
    identity: Identity,
    app: Router,
    id: String,
    user: String,
    secret: String,
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
                    oidc_redirect_uris: Some(vec![CALLBACK.into()]),
                    saml_enabled: Some(true),
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
        let identity = Identity::new(store.clone());
        let app = api::router_with_identity(
            store.clone(),
            "greendale-instance".into(),
            HOST.into(),
            identity.clone(),
        );
        Self {
            _temporary: temporary,
            store,
            identity,
            app,
            id: environment.id,
            user: user.id,
            secret: environment.settings.oidc_client_secret,
        }
    }
    async fn code(&self) -> String {
        self.code_with(&[]).await
    }
    async fn code_with(&self, extra: &[(&str, &str)]) -> String {
        let mut values = vec![
            ("client_id", "greendale"),
            ("redirect_uri", CALLBACK),
            ("response_type", "code"),
            ("scope", "openid email offline_access"),
            ("user_id", self.user.as_str()),
        ];
        values.extend_from_slice(extra);
        let (status, headers, body) = send(
            self.app.clone(),
            "GET",
            &format!(
                "/oidc/greendale/authorize?{}",
                serde_urlencoded::to_string(values).unwrap()
            ),
            "",
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FOUND,
            "{}",
            String::from_utf8_lossy(&body)
        );
        let url = url::Url::parse(headers["location"].to_str().unwrap()).unwrap();
        url.query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned()
    }
    fn form(&self, kind: &str, token: &str) -> String {
        serde_urlencoded::to_string([
            ("grant_type", kind),
            ("client_id", "greendale"),
            ("client_secret", &self.secret),
            (
                if kind == "refresh_token" {
                    "refresh_token"
                } else {
                    "code"
                },
                token,
            ),
            ("redirect_uri", CALLBACK),
        ])
        .unwrap()
    }
    async fn redeem(&self, form: &str) -> (StatusCode, HeaderMap, Value) {
        let (status, headers, bytes) =
            send(self.app.clone(), "POST", "/oidc/greendale/token", form).await;
        (status, headers, serde_json::from_slice(&bytes).unwrap())
    }
    async fn wait_in_flight(&self, count: i32) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if self
                    .identity
                    .resilience_run(&self.id)
                    .unwrap()
                    .unwrap()
                    .in_flight
                    == count
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
}
async fn send(
    app: Router,
    method: &str,
    path: &str,
    body: &str,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = app
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("Host", HOST)
                .header(
                    "Content-Type",
                    if path.starts_with("/api/") {
                        "application/json"
                    } else {
                        "application/x-www-form-urlencoded"
                    },
                )
                .header("X-Scimtest-Instance-Token", "greendale-instance")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, body)
}
fn claims(token: &Value) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(
                token["id_token"]
                    .as_str()
                    .unwrap()
                    .split('.')
                    .nth(1)
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn token_outages_count_valid_requests_and_recover_without_consuming_grants() {
    let f = Fixture::new();
    let code = f.code().await;
    let form = f.form("authorization_code", &code);
    f.identity.arm_resilience(&f.id, "token-outage", 2).unwrap();
    for invalid in [
        form.replace(&f.secret, "wrong-secret"),
        form.replace(&code, "unknown-code"),
        form.replace("authorization_code", "password"),
    ] {
        assert!(f.redeem(&invalid).await.0.is_client_error());
        assert_eq!(
            f.identity.resilience_run(&f.id).unwrap().unwrap().remaining,
            2
        );
    }
    for remaining in [1, 0] {
        let (status, headers, body) = f.redeem(&form).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(headers["retry-after"], "5");
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(body["error"], "temporarily_unavailable");
        assert_eq!(
            f.identity.resilience_run(&f.id).unwrap().unwrap().remaining,
            remaining
        );
    }
    let (status, _, body) = f.redeem(&form).await;
    assert_eq!(status, StatusCode::OK);
    let refresh = f.form("refresh_token", body["refresh_token"].as_str().unwrap());
    f.identity.arm_resilience(&f.id, "token-outage", 1).unwrap();
    assert_eq!(f.redeem(&refresh).await.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(f.redeem(&refresh).await.0, StatusCode::OK);
    assert_eq!(f.redeem(&refresh).await.0, StatusCode::BAD_REQUEST);
    let run = f.identity.resilience_run(&f.id).unwrap().unwrap();
    assert_eq!(run.state, "completed");
    assert_eq!(run.decisions[0].phase, "token (refresh_token)");
}

#[tokio::test]
async fn canceling_slow_code_or_refresh_requests_releases_the_grant_and_keeps_the_scenario_armed() {
    for kind in ["authorization_code", "refresh_token"] {
        let f = Fixture::new();
        f.store.active_signing_key(&f.id).unwrap();
        let mut token = f.code().await;
        if kind == "refresh_token" {
            let (_, _, body) = f.redeem(&f.form("authorization_code", &token)).await;
            token = body["refresh_token"].as_str().unwrap().into();
        }
        f.identity.arm_resilience(&f.id, "slow-token", 0).unwrap();
        let app = f.app.clone();
        let form = f.form(kind, &token);
        let delayed = form.clone();
        let task =
            tokio::spawn(async move { send(app, "POST", "/oidc/greendale/token", &delayed).await });
        f.wait_in_flight(1).await;
        assert_eq!(f.redeem(&form).await.0, StatusCode::BAD_REQUEST);
        let unrelated = f.code().await;
        assert_eq!(
            f.redeem(&f.form("authorization_code", &unrelated)).await.0,
            StatusCode::OK
        );
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        f.wait_in_flight(0).await;
        let run = f.identity.resilience_run(&f.id).unwrap().unwrap();
        assert_eq!(run.state, "armed");
        assert_eq!(run.remaining, 1);
        assert_eq!(run.decisions[0].outcome, "canceled");
        f.identity.disarm_resilience(&f.id).unwrap();
        assert_eq!(f.redeem(&form).await.0, StatusCode::OK);
    }
}

#[tokio::test]
async fn slow_redemption_rechecks_user_changes_and_disarming_preserves_progress() {
    let cases = [(false, "authorization_code"), (true, "refresh_token")];
    let tasks = cases
        .into_iter()
        .map(|(deactivate, kind)| async move {
            let f = Fixture::new();
            let mut token = f.code().await;
            if kind == "refresh_token" {
                let (_, _, body) = f.redeem(&f.form("authorization_code", &token)).await;
                token = body["refresh_token"].as_str().unwrap().into();
            }
            f.identity.arm_resilience(&f.id, "slow-token", 0).unwrap();
            let app = f.app.clone();
            let form = f.form(kind, &token);
            let task =
                tokio::spawn(
                    async move { send(app, "POST", "/oidc/greendale/token", &form).await },
                );
            f.wait_in_flight(1).await;
            f.store
                .update_user(
                    &f.id,
                    &f.user,
                    UserPatch {
                        active: Some(!deactivate),
                        email: Some("troy.barnes@greendale.edu".into()),
                        ..Default::default()
                    },
                )
                .unwrap();
            if !deactivate {
                assert!(f.identity.disarm_resilience(&f.id).unwrap());
            }
            let (status, _, bytes) = task.await.unwrap();
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            let run = f.identity.resilience_run(&f.id).unwrap().unwrap();
            if deactivate {
                assert_eq!(status, StatusCode::BAD_REQUEST);
                assert_eq!(body["error"], "invalid_grant");
                assert_eq!(run.state, "completed");
            } else {
                assert_eq!(status, StatusCode::OK);
                assert_eq!(claims(&body)["email"], "troy.barnes@greendale.edu");
                assert_eq!(run.state, "disarmed");
                assert_eq!(run.remaining, 1);
            }
        })
        .collect::<Vec<_>>();
    let mut handles = Vec::new();
    for task in tasks {
        handles.push(tokio::spawn(task));
    }
    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn stale_jwks_preserves_retired_keys_then_recovers() {
    let f = Fixture::new();
    f.store.active_signing_key(&f.id).unwrap();
    f.store
        .rotate_signing_key(
            &f.id,
            chrono::Duration::hours(1),
            scimtest_core::signing::CertificateValidity::Standard,
        )
        .unwrap();
    let active = f.store.active_signing_key(&f.id).unwrap().stored.kid;
    f.identity.arm_resilience(&f.id, "stale-jwks", 1).unwrap();
    assert_eq!(
        send(
            f.app.clone(),
            "GET",
            "/oidc/greendale/.well-known/openid-configuration",
            ""
        )
        .await
        .0,
        StatusCode::OK
    );
    for count in [1, 2] {
        let (status, _, bytes) = send(f.app.clone(), "GET", "/oidc/greendale/jwks", "").await;
        assert_eq!(status, StatusCode::OK);
        let keys: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(keys["keys"].as_array().unwrap().len(), count);
        assert_eq!(
            keys["keys"]
                .as_array()
                .unwrap()
                .iter()
                .any(|key| key["kid"] == active),
            count == 2
        );
    }
}

#[tokio::test]
async fn flow_presets_apply_once_after_explicit_and_manually_armed_faults() {
    let f = Fixture::new();
    f.identity
        .arm_resilience(&f.id, "expired-token", 99)
        .unwrap();
    f.identity
        .arm_faults(
            &f.id,
            Faults {
                drop_claims: vec!["email".into()],
                ..Default::default()
            },
        )
        .unwrap();
    let code = f.code_with(&[("fault_tamper", "wrong_audience")]).await;
    let (_, _, body) = f.redeem(&f.form("authorization_code", &code)).await;
    assert_ne!(claims(&body)["aud"], "greendale");
    assert_eq!(
        f.identity.resilience_run(&f.id).unwrap().unwrap().remaining,
        1
    );
    let code = f.code().await;
    let (_, _, body) = f.redeem(&f.form("authorization_code", &code)).await;
    assert!(claims(&body).get("email").is_none());
    assert_eq!(
        f.identity.resilience_run(&f.id).unwrap().unwrap().remaining,
        1
    );
    let code = f.code().await;
    let (_, _, body) = f.redeem(&f.form("authorization_code", &code)).await;
    let claims = claims(&body);
    assert!(claims["exp"].as_i64() < claims["iat"].as_i64());
    assert_eq!(
        f.identity.resilience_run(&f.id).unwrap().unwrap().state,
        "completed"
    );
    let code = f.code().await;
    let (_, _, body) = f.redeem(&f.form("authorization_code", &code)).await;
    let healthy = crate::claims(&body);
    assert!(healthy["exp"].as_i64() > healthy["iat"].as_i64());
    f.identity
        .arm_resilience(&f.id, "saml-auth-failed", 0)
        .unwrap();
    let form = serde_urlencoded::to_string([("user_id", f.user.as_str())]).unwrap();
    let (status, _, bytes) = send(f.app.clone(), "POST", "/saml/greendale/sso", &form).await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8(bytes).unwrap();
    let xml = String::from_utf8(
        STANDARD
            .decode(
                html.split("name=\"SAMLResponse\" value=\"")
                    .nth(1)
                    .unwrap()
                    .split('"')
                    .next()
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    assert!(xml.contains("status:AuthnFailed"));
    assert!(!xml.contains("<saml:Assertion"));
}

#[tokio::test]
async fn scenario_availability_counts_and_conflicts_match_environment_protocols() {
    let f = Fixture::new();
    assert!(f.identity.arm_resilience(&f.id, "unknown", 1).is_err());
    for count in [-1, 21] {
        assert!(
            f.identity
                .arm_resilience(&f.id, "token-outage", count)
                .is_err()
        );
    }
    let run = f.identity.arm_resilience(&f.id, "stale-jwks", 20).unwrap();
    assert_eq!(run.remaining, 20);
    assert!(f.identity.arm_resilience(&f.id, "token-outage", 2).is_err());
    assert!(f.identity.disarm_resilience(&f.id).unwrap());
    let saml = f
        .store
        .create_environment(EnvironmentInput {
            name: "City College".into(),
            settings: SettingsPatch {
                saml_enabled: Some(true),
                saml_acs_url: Some("https://citycollege.example/acs".into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
    let presets = f.identity.resilience_presets(&saml.id).unwrap();
    assert!(presets.iter().any(|preset| preset.id == "saml-auth-failed"));
    assert!(!presets.iter().any(|preset| preset.id == "token-outage"));
    assert!(
        f.identity
            .arm_resilience(&saml.id, "token-outage", 1)
            .is_err()
    );
    let none = f
        .store
        .create_environment(EnvironmentInput {
            name: "Greendale Directory".into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(f.identity.resilience_presets(&none.id).unwrap().len(), 2);
}

#[tokio::test]
async fn scenario_api_preserves_go_shapes_counts_and_conflict_behavior() {
    let f = Fixture::new();
    let path = format!("/api/v1/environments/{}/scenarios", f.id);
    let (status, _, body) = send(f.app.clone(), "GET", &path, "").await;
    assert_eq!(status, StatusCode::OK);
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert!(value["run"].is_null());
    let presets = value["presets"].as_array().unwrap();
    assert_eq!(presets.len(), 10);
    let preset = presets
        .iter()
        .find(|preset| preset["ID"] == "slow-token")
        .unwrap();
    assert_eq!(preset["Action"]["Delay"], 3_000_000_000i64);
    assert!(preset["Action"]["Faults"]["Tamper"].is_null());
    let preset = presets
        .iter()
        .find(|preset| preset["ID"] == "expired-token")
        .unwrap();
    assert_eq!(preset["Action"]["Faults"]["IDTokenTTL"], -60_000_000_000i64);
    assert_eq!(preset["Action"]["Faults"]["IDTokenTTLSet"], true);
    for count in [
        json!(1.5),
        json!(true),
        json!(" 2"),
        json!("2.0"),
        json!([]),
    ] {
        let (status, _, _) = send(
            f.app.clone(),
            "POST",
            &format!("{path}/arm"),
            &json!({"preset_id":"token-outage","count":count}).to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    for count in [json!(-1), json!(21), json!(2147483648i64)] {
        let (status, _, _) = send(
            f.app.clone(),
            "POST",
            &format!("{path}/arm"),
            &json!({"preset_id":"token-outage","count":count}).to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }
    f.identity
        .arm_faults(
            &f.id,
            Faults {
                break_signature: true,
                ..Default::default()
            },
        )
        .unwrap();
    for count in [json!("2"), json!(2.0)] {
        let (status, _, body) = send(
            f.app.clone(),
            "POST",
            &format!("{path}/arm"),
            &json!({"preset_id":"token-outage","count":count}).to_string(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&body)
        );
        let run: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(run["Total"], 2);
        assert_eq!(run["State"], "armed");
        assert!(run["Decisions"].is_null());
        assert_eq!(run["Action"]["Status"], 503);
        assert_eq!(run["Action"]["RunID"], "");
        assert!(!f.identity.faults(&f.id).unwrap().active());
        assert_eq!(
            send(
                f.app.clone(),
                "POST",
                &format!("{path}/arm"),
                r#"{"preset_id":"token-outage"}"#
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let (status, _, body) = send(f.app.clone(), "POST", &format!("{path}/disarm"), "").await;
        assert_eq!(status, StatusCode::OK);
        let run: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(run["State"], "disarmed");
        assert_eq!(run["Decisions"][0]["Outcome"], "disarmed");
        assert_eq!(
            send(f.app.clone(), "POST", &format!("{path}/disarm"), "")
                .await
                .0,
            StatusCode::CONFLICT
        );
        let (_, _, body) = send(f.app.clone(), "GET", &path, "").await;
        assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["run"], run);
    }
    assert_eq!(
        send(
            f.app.clone(),
            "POST",
            &format!("{path}/arm"),
            r#"{"preset_id":"slow-token","count":9999999999}"#
        )
        .await
        .0,
        StatusCode::CREATED
    );
    f.identity.disarm_resilience(&f.id).unwrap();
    assert_eq!(
        send(
            f.app.clone(),
            "POST",
            &format!("{path}/arm"),
            r#"{"preset_id":"unknown"}"#
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn an_actual_client_timeout_releases_the_delayed_token_reservation() {
    let f = Fixture::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = f.app.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    f.identity.arm_resilience(&f.id, "slow-token", 0).unwrap();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
        .unwrap();
    let result = client
        .post(format!("http://{address}/oidc/greendale/token"))
        .header("Host", HOST)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(f.form("client_credentials", ""))
        .send()
        .await;
    assert!(result.unwrap_err().is_timeout());
    f.wait_in_flight(0).await;
    let run = f.identity.resilience_run(&f.id).unwrap().unwrap();
    assert_eq!(run.state, "armed");
    assert_eq!(run.remaining, 1);
    assert_eq!(run.decisions[0].outcome, "canceled");
    server.abort();
}
