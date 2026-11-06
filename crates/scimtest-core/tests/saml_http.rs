#[path = "saml_http/logout.rs"]
mod logout;
#[allow(dead_code)]
mod support;
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
use scimtest_core::{Store, api, configuration::SettingsPatch, model::*};
use serde_json::{Value, json};
use tower::ServiceExt;
const HOST: &str = "127.0.0.1:19524";
const CALLBACK: &str = "https://greendale.example/callback";
struct Fixture {
    _temporary: tempfile::TempDir,
    store: Store,
    app: Router,
    id: String,
    troy: String,
    abed: String,
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
                    saml_entity_id: Some("urn:greendale:sp".into()),
                    saml_acs_url: Some("https://greendale.example/acs".into()),
                    saml_slo_url: Some("https://greendale.example/slo?campus=greendale".into()),
                    ..Default::default()
                },
                ..Default::default()
            })
            .unwrap();
        let troy = store
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
        let abed = store
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
        let app = api::router(store.clone(), "greendale-instance".into(), HOST.into());
        Self {
            _temporary: temporary,
            store,
            app,
            id: environment.id,
            troy: troy.id,
            abed: abed.id,
            secret: environment.settings.oidc_client_secret,
        }
    }
    async fn send(
        &self,
        method: &str,
        path: &str,
        body: &str,
        json_body: bool,
        cookie: &str,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("Host", HOST);
        if path.starts_with("/api/") {
            request = request.header("X-Scimtest-Instance-Token", "greendale-instance");
        }
        if !body.is_empty() {
            request = request.header(
                "Content-Type",
                if json_body {
                    "application/json"
                } else {
                    "application/x-www-form-urlencoded"
                },
            );
        }
        if !cookie.is_empty() {
            request = request.header("Cookie", cookie);
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(body.to_owned())).unwrap())
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
    async fn admin(&self, suffix: &str) -> Value {
        let (status, _, bytes) = self
            .send(
                "GET",
                &format!("/api/v1/environments/{}{suffix}", self.id),
                "",
                false,
                "",
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
        serde_json::from_slice(&bytes).unwrap()
    }
    fn authn_request(&self, force: bool) -> String {
        format!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_greendale-request" Version="2.0" Destination="http://{HOST}/saml/greendale/sso" AssertionConsumerServiceURL="https://greendale.example/acs" ForceAuthn="{force}"><saml:Issuer>urn:greendale:sp</saml:Issuer><samlp:RequestedAuthnContext><saml:AuthnContextClassRef>https://refeds.org/profile/mfa</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>"#
        )
    }
}
fn query(values: &[(&str, String)]) -> String {
    serde_urlencoded::to_string(values).unwrap()
}
fn posted_xml(body: &[u8]) -> String {
    let html = std::str::from_utf8(body).unwrap();
    let encoded = html
        .split("name=\"SAMLResponse\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    String::from_utf8(STANDARD.decode(encoded).unwrap()).unwrap()
}
fn session_cookie(headers: &HeaderMap) -> String {
    headers["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}
fn document(xml: &str) -> bergshamra::xml::Document<'_> {
    bergshamra::xml::uppsala::parse(xml).unwrap()
}

#[tokio::test]
async fn saml_and_oidc_share_browser_sessions_and_fresh_authentication_rules() {
    let f = Fixture::new();
    let (status, _, body) = f.send("GET", "/saml/greendale/sso", "", false, "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("SAML sign-in"));
    let path = format!(
        "/saml/greendale/sso?{}",
        query(&[
            ("user_id", f.troy.clone()),
            ("authn_strength", "mfa".into()),
            ("RelayState", "study-group".into())
        ])
    );
    let (status, headers, body) = f.send("GET", &path, "", false, "").await;
    assert_eq!(status, StatusCode::OK);
    let cookie = session_cookie(&headers);
    let xml = posted_xml(&body);
    let doc = document(&xml);
    let session = doc
        .get_attribute(
            doc.get_elements_by_tag_name("AuthnStatement")[0],
            "SessionIndex",
        )
        .unwrap()
        .to_owned();
    let verify=support::bridge_input("verify-saml",&f._temporary.path().join("state.db"),&serde_json::to_vec(&json!({"xml":xml,"certificate_pem":f.store.active_signing_key(&f.id).unwrap().stored.certificate_pem})).unwrap());
    assert_eq!(
        serde_json::from_slice::<Value>(&verify).unwrap()["assertion_valid"],
        true
    );
    let path = format!(
        "/oidc/greendale/authorize?{}",
        query(&[
            ("client_id", "greendale".into()),
            ("redirect_uri", CALLBACK.into()),
            ("response_type", "code".into()),
            ("scope", "openid profile email".into()),
            ("prompt", "none".into())
        ])
    );
    let (status, headers, _) = f.send("GET", &path, "", false, &cookie).await;
    assert_eq!(status, StatusCode::FOUND);
    let redirect = url::Url::parse(headers["location"].to_str().unwrap()).unwrap();
    let code = redirect
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned();
    let form = query(&[
        ("grant_type", "authorization_code".into()),
        ("code", code),
        ("redirect_uri", CALLBACK.into()),
        ("client_id", "greendale".into()),
        ("client_secret", f.secret.clone()),
    ]);
    let (status, _, body) = f
        .send("POST", "/oidc/greendale/token", &form, false, "")
        .await;
    assert_eq!(status, StatusCode::OK);
    let token: Value = serde_json::from_slice(&body).unwrap();
    let claims: Value = serde_json::from_slice(
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
    .unwrap();
    assert_eq!(claims["amr"], json!(["pwd", "otp", "mfa"]));
    assert_eq!(claims["sid"], cookie.split_once('=').unwrap().1);
    let sessions = f.admin("/sessions").await;
    assert_eq!(sessions["sessions"].as_array().unwrap().len(), 1);
    assert_eq!(
        sessions["sessions"][0]["protocols"],
        json!(["saml", "oidc"])
    );
    assert_eq!(sessions["sessions"][0]["saml_session_index"], session);
    let path = format!(
        "/saml/greendale/sso?{}",
        query(&[
            ("continue_session", "1".into()),
            ("SAMLRequest", STANDARD.encode(f.authn_request(true)))
        ])
    );
    assert_eq!(
        f.send("GET", &path, "", false, &cookie).await.0,
        StatusCode::BAD_REQUEST
    );
    let path = format!(
        "/saml/greendale/sso?{}",
        query(&[("user_id", f.abed.clone())])
    );
    let (_, headers, _) = f.send("GET", &path, "", false, &cookie).await;
    assert_ne!(session_cookie(&headers), cookie);
    let sessions = f.admin("/sessions").await;
    assert_eq!(sessions["sessions"].as_array().unwrap().len(), 1);
    assert_eq!(sessions["sessions"][0]["user_id"], f.abed);
}

#[tokio::test]
async fn saml_metadata_rollover_and_certificate_download_publish_real_keys() {
    let f = Fixture::new();
    let (status, headers, body) = f
        .send("GET", "/saml/greendale/metadata?download=1", "", false, "")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers["content-type"],
        "application/samlmetadata+xml; charset=utf-8"
    );
    assert!(headers.contains_key("content-disposition"));
    let xml = String::from_utf8(body).unwrap();
    let doc = document(&xml);
    assert_eq!(doc.get_elements_by_tag_name("KeyDescriptor").len(), 1);
    f.store
        .rotate_signing_key(
            &f.id,
            chrono::Duration::hours(1),
            scimtest_core::signing::CertificateValidity::Standard,
        )
        .unwrap();
    let (_, _, body) = f
        .send("GET", "/saml/greendale/metadata", "", false, "")
        .await;
    let xml = String::from_utf8(body).unwrap();
    let doc = document(&xml);
    assert_eq!(doc.get_elements_by_tag_name("KeyDescriptor").len(), 2);
    let (status, _, body) = f
        .send("GET", "/saml/greendale/certificate.pem", "", false, "")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        String::from_utf8(body).unwrap(),
        f.store
            .active_signing_key(&f.id)
            .unwrap()
            .stored
            .certificate_pem
    );
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/saml/greendale/metadata")
                .header("Host", "citycollege.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn json_saml_sign_in_checks_pinned_post_signatures_before_choosing_a_user() {
    let f = Fixture::new();
    let key = f.store.shared_signing_key().unwrap();
    f.store
        .update_environment(
            &f.id,
            EnvironmentPatch {
                settings: SettingsPatch {
                    saml_request_certificate_pem: Some(key.stored.certificate_pem.clone()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    let path = format!("/api/v1/environments/{}/saml/sign-in", f.id);
    let unsigned = f.authn_request(false);
    let request = json!({"user_id":f.troy,"saml_request":STANDARD.encode(&unsigned)}).to_string();
    assert_eq!(
        f.send("POST", &path, &request, true, "").await.0,
        StatusCode::BAD_REQUEST
    );
    let signed = scimtest_core::saml::sign_xml(&unsigned, &key).unwrap();
    let request=json!({"user_id":f.troy,"saml_request":STANDARD.encode(&signed),"relay_state":"study & group"}).to_string();
    let (status, headers, body) = f.send("POST", &path, &request, true, "").await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert!(headers.contains_key("set-cookie"));
    let response: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["relay_state"], "study & group");
    let xml = String::from_utf8(
        STANDARD
            .decode(response["saml_response"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let doc = document(&xml);
    assert_eq!(
        doc.get_attribute(doc.document_element().unwrap(), "InResponseTo"),
        Some("_greendale-request")
    );
    assert!(xml.contains("https://refeds.org/profile/mfa"));
    assert_eq!(
        f.admin("/inspections/saml").await.as_array().unwrap().len(),
        1
    );
    let wrong = signed.replace("urn:greendale:sp", "urn:city-college:sp");
    let request = json!({"user_id":f.troy,"saml_request":STANDARD.encode(wrong)}).to_string();
    assert_eq!(
        f.send("POST", &path, &request, true, "").await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn go_signed_redirect_requests_preserve_raw_query_across_the_browser_chooser() {
    let f = Fixture::new();
    let key = f.store.shared_signing_key().unwrap();
    f.store
        .update_environment(
            &f.id,
            EnvironmentPatch {
                settings: SettingsPatch {
                    saml_request_certificate_pem: Some(key.stored.certificate_pem.clone()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    for algorithm in [256, 384, 512] {
        let bytes = support::bridge_input(
            "sign-saml-redirect",
            &f._temporary.path().join("state.db"),
            &serde_json::to_vec(&json!({
            "xml":f.authn_request(false),"private_key_pem":key.stored.private_key_pem,
            "algorithm":algorithm,"relay_state":"study & group + /"}))
            .unwrap(),
        );
        let query = String::from_utf8(bytes).unwrap();
        scimtest_core::saml::verify_redirect(
            &query,
            "SAMLRequest",
            "AuthnRequest",
            &key.stored.certificate_pem,
        )
        .unwrap();
        let path = format!("/saml/greendale/sso?{query}");
        assert_eq!(f.send("GET", &path, "", false, "").await.0, StatusCode::OK);
        let body = superfluous_chooser_body(&f.troy);
        let (status, _, body) = f.send("POST", &path, &body, false, "").await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert!(
            String::from_utf8(body)
                .unwrap()
                .contains("study &amp; group + /")
        );
        let request = json!({"user_id":f.troy,"redirect_query":query}).to_string();
        let (status, _, body) = f
            .send(
                "POST",
                &format!("/api/v1/environments/{}/saml/sign-in", f.id),
                &request,
                true,
                "",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["relay_state"], "study & group + /");
        for tampered in [
            format!("{query}&RelayState=city-college"),
            format!("{query}&SAMLRequest=forged"),
            query.replace("SAMLRequest=", "%53AMLRequest="),
            query.replace("study+%26+group", "city-college"),
        ] {
            assert!(
                scimtest_core::saml::verify_redirect(
                    &tampered,
                    "SAMLRequest",
                    "AuthnRequest",
                    &key.stored.certificate_pem
                )
                .is_err()
            );
            assert_eq!(
                f.send(
                    "GET",
                    &format!("/saml/greendale/sso?{tampered}"),
                    "",
                    false,
                    ""
                )
                .await
                .0,
                StatusCode::BAD_REQUEST
            );
        }
    }
}
fn superfluous_chooser_body(user: &str) -> String {
    query(&[
        ("user_id", user.into()),
        ("SAMLRequest", STANDARD.encode("<forged/>")),
        ("RelayState", "city-college".into()),
    ])
}

#[tokio::test]
async fn a_cookie_from_another_environment_does_not_end_its_session() {
    let f = Fixture::new();
    let (_, headers, _) = f
        .send(
            "POST",
            "/saml/greendale/sso",
            &query(&[("user_id", f.troy.clone())]),
            false,
            "",
        )
        .await;
    let original = session_cookie(&headers);
    let environment = f
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
    let user = f
        .store
        .create_user(
            &environment.id,
            UserInput {
                given_name: "Abed".into(),
                family_name: "Nadir".into(),
                email: "abed@citycollege.example".into(),
                ..Default::default()
            },
        )
        .unwrap();
    let forged = format!(
        "scimtest_chooser_{}={}",
        environment.slug,
        original.split_once('=').unwrap().1
    );
    let (status, headers, body) = f
        .send(
            "POST",
            &format!("/saml/{}/sso", environment.slug),
            &query(&[("user_id", user.id)]),
            false,
            &forged,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_ne!(
        session_cookie(&headers).split_once('=').unwrap().1,
        original.split_once('=').unwrap().1
    );
    let sessions = f.admin("/sessions").await;
    assert_eq!(sessions["sessions"].as_array().unwrap().len(), 1);
    assert_eq!(
        sessions["sessions"][0]["session_id"],
        original.split_once('=').unwrap().1
    );
}

#[tokio::test]
async fn wrapping_and_nameid_comment_faults_keep_the_genuine_go_verified_signature() {
    let f = Fixture::new();
    let key = f.store.active_signing_key(&f.id).unwrap();
    for (mode, fault, want_valid) in [
        ("assertion", "xsw_assertion", 1),
        ("response", "xsw_response", 1),
        ("both", "xsw_response", 2),
        ("assertion", "nameid_comment", 1),
        ("response", "nameid_comment", 1),
        ("both", "nameid_comment", 2),
    ] {
        f.store
            .update_environment(
                &f.id,
                EnvironmentPatch {
                    settings: SettingsPatch {
                        saml_signing_mode: Some(mode.into()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .unwrap();
        let body = query(&[("user_id", f.troy.clone()), ("fault_tamper", fault.into())]);
        let (status, _, body) = f
            .send("POST", "/saml/greendale/sso", &body, false, "")
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let xml = posted_xml(&body);
        let doc = document(&xml);
        let names = doc.get_elements_by_tag_name("NameID");
        let first = doc.text_content_deep(names[0]);
        if fault == "nameid_comment" {
            assert_eq!(first, "abed@greendale.edu.scimtest-forged.example");
            assert!(xml.contains("abed@greendale.edu<!---->.scimtest-forged.example"));
        } else {
            assert_eq!(first, "abed@greendale.edu");
            assert!(
                names
                    .iter()
                    .any(|node| doc.text_content_deep(*node) == "troy@greendale.edu")
            );
        }
        let valid = support::bridge_input("verify-saml",&f._temporary.path().join("state.db"),&serde_json::to_vec(&json!({"xml":xml,"certificate_pem":key.stored.certificate_pem,"scan_signatures":true})).unwrap());
        let valid: Value = serde_json::from_slice(&valid).unwrap();
        assert_eq!(
            valid.as_array().unwrap().len(),
            want_valid,
            "{mode}/{fault}: {xml}"
        );
    }
    f.store
        .update_environment(
            &f.id,
            EnvironmentPatch {
                settings: SettingsPatch {
                    saml_signing_mode: Some("both".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        f.send(
            "POST",
            "/saml/greendale/sso",
            &query(&[
                ("user_id", f.troy.clone()),
                ("fault_tamper", "xsw_assertion".into())
            ]),
            false,
            ""
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    f.store.delete_user(&f.id, &f.abed).unwrap();
    assert_eq!(
        f.send(
            "POST",
            "/saml/greendale/sso",
            &query(&[
                ("user_id", f.troy.clone()),
                ("fault_tamper", "nameid_comment".into())
            ]),
            false,
            ""
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}
