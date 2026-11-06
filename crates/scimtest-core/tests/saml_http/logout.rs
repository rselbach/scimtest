use super::*;
use chrono::{Duration, Utc};
use scimtest_core::{saml::*, signing::SigningKey};

impl Fixture {
    fn pin_sp(&self) -> SigningKey {
        let key = self.store.shared_signing_key().unwrap();
        self.store
            .update_environment(
                &self.id,
                EnvironmentPatch {
                    settings: SettingsPatch {
                        saml_request_certificate_pem: Some(key.stored.certificate_pem.clone()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .unwrap();
        key
    }
    async fn saml_session(&self, user: &str) -> (String, Value) {
        let (status, headers, body) = self
            .send(
                "POST",
                "/saml/greendale/sso",
                &query(&[("user_id", user.into())]),
                false,
                "",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let cookie = session_cookie(&headers);
        let id = cookie.split_once('=').unwrap().1;
        let sessions = self.admin("/sessions").await;
        let session = sessions["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|session| session["session_id"] == id)
            .unwrap()
            .clone();
        (cookie, session)
    }
    async fn logout_message(
        &self,
        key: &SigningKey,
        binding: &str,
        param: &str,
        xml: &str,
        cookie: &str,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        if binding == "post" {
            let signed = sign_xml(xml, key).unwrap();
            return self
                .send(
                    "POST",
                    "/saml/greendale/slo",
                    &query(&[
                        (param, STANDARD.encode(signed)),
                        ("RelayState", "study & group".into()),
                    ]),
                    false,
                    cookie,
                )
                .await;
        }
        let signed = support::bridge_input("sign-saml-redirect",&self._temporary.path().join("state.db"),&serde_json::to_vec(&json!({"xml":xml,"private_key_pem":key.stored.private_key_pem,"param":param,"relay_state":"study & group"})).unwrap());
        self.send(
            "GET",
            &format!("/saml/greendale/slo?{}", String::from_utf8(signed).unwrap()),
            "",
            false,
            cookie,
        )
        .await
    }
    fn verify_outbound(
        &self,
        binding: &str,
        param: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> String {
        let key = self.store.active_signing_key(&self.id).unwrap();
        if binding == "post" {
            let xml = posted_xml(body);
            let result = support::bridge_input(
                "verify-saml",
                &self._temporary.path().join("state.db"),
                &serde_json::to_vec(
                    &json!({"xml":xml,"certificate_pem":key.stored.certificate_pem}),
                )
                .unwrap(),
            );
            assert_eq!(
                serde_json::from_slice::<Value>(&result).unwrap()["message_valid"],
                true
            );
            return xml;
        }
        let url = url::Url::parse(headers["location"].to_str().unwrap()).unwrap();
        assert!(
            url.query_pairs()
                .any(|(key, value)| key == "campus" && value == "greendale")
        );
        let result = support::bridge_input("verify-saml-redirect",&self._temporary.path().join("state.db"),&serde_json::to_vec(&json!({"query":url.query().unwrap(),"certificate_pem":key.stored.certificate_pem,"param":param})).unwrap());
        assert_eq!(serde_json::from_slice::<Value>(&result).unwrap(), true);
        assert!(
            url.query_pairs()
                .any(|(key, value)| key == "RelayState" && value == "study & group")
        );
        decode_message(&url.query_pairs().find(|(key, _)| key == param).unwrap().1).unwrap()
    }
}
fn request_xml(session: &Value, name: &str, now: chrono::DateTime<Utc>) -> String {
    build_logout_request(
        "urn:greendale:sp",
        &format!("http://{HOST}/saml/greendale/slo"),
        name,
        "",
        session["saml_session_index"].as_str().unwrap(),
        now,
    )
    .1
}

#[tokio::test]
async fn sp_logout_checks_signature_identity_time_and_session_before_ending_the_target() {
    for binding in ["redirect", "post"] {
        let f = Fixture::new();
        let key = f.pin_sp();
        let (cookie, target) = f.saml_session(&f.troy).await;
        let (_, other) = f.saml_session(&f.troy).await;
        let (_, abed) = f.saml_session(&f.abed).await;
        let request = request_xml(&target, "troy@greendale.edu", Utc::now());
        for invalid in [
            request.replace("urn:greendale:sp", "urn:city-college:sp"),
            request.replace("samlp:LogoutRequest", "samlp:AuthnRequest"),
        ] {
            assert_eq!(
                f.logout_message(&key, binding, "SAMLRequest", &invalid, &cookie)
                    .await
                    .0,
                StatusCode::BAD_REQUEST
            );
        }
        let unsigned = query(&[("SAMLRequest", STANDARD.encode(&request))]);
        assert_eq!(
            f.send("POST", "/saml/greendale/slo", &unsigned, false, &cookie)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        for invalid in [
            request_xml(&target, "abed@greendale.edu", Utc::now()),
            request_xml(
                &target,
                "troy@greendale.edu",
                Utc::now() - Duration::minutes(10),
            ),
            request.replace(
                &format!("http://{HOST}/saml/greendale/slo"),
                "https://citycollege.example/slo",
            ),
        ] {
            let (status, headers, body) = f
                .logout_message(&key, binding, "SAMLRequest", &invalid, &cookie)
                .await;
            assert_eq!(
                status,
                if binding == "post" {
                    StatusCode::OK
                } else {
                    StatusCode::FOUND
                },
                "{}",
                String::from_utf8_lossy(&body)
            );
            assert!(!headers.contains_key("set-cookie"));
            let xml = f.verify_outbound(binding, "SAMLResponse", &headers, &body);
            assert!(xml.contains("status:Requester"));
            assert_eq!(
                f.admin("/sessions").await["sessions"]
                    .as_array()
                    .unwrap()
                    .len(),
                3
            );
        }
        let (status, headers, body) = f
            .logout_message(&key, binding, "SAMLRequest", &request, &cookie)
            .await;
        assert_eq!(
            status,
            if binding == "post" {
                StatusCode::OK
            } else {
                StatusCode::FOUND
            }
        );
        assert!(
            headers["set-cookie"]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
        let xml = f.verify_outbound(binding, "SAMLResponse", &headers, &body);
        assert!(xml.contains("status:Success"));
        let sessions = f.admin("/sessions").await;
        let sessions = sessions["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 2);
        assert!(
            sessions
                .iter()
                .any(|session| session["session_id"] == other["session_id"])
        );
        assert!(
            sessions
                .iter()
                .any(|session| session["session_id"] == abed["session_id"])
        );
    }
}

#[tokio::test]
async fn idp_logout_signs_both_bindings_and_correlates_the_sp_answer_once() {
    for binding in ["redirect", "post"] {
        let f = Fixture::new();
        let key = f.pin_sp();
        let (_, session) = f.saml_session(&f.troy).await;
        let path = format!("/api/v1/environments/{}/saml/logout", f.id);
        let input = json!({"session_id":session["session_id"],"binding":binding}).to_string();
        let (status, _, body) = f.send("POST", &path, &input, true, "").await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let outbound: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            f.admin("/sessions").await["sessions"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let encoded = if binding == "post" {
            let encoded = outbound["form"]["SAMLRequest"].as_str().unwrap();
            let xml = decode_message(encoded).unwrap();
            let verified = support::bridge_input("verify-saml",&f._temporary.path().join("state.db"),&serde_json::to_vec(&json!({"xml":xml,"certificate_pem":f.store.active_signing_key(&f.id).unwrap().stored.certificate_pem})).unwrap());
            assert_eq!(
                serde_json::from_slice::<Value>(&verified).unwrap()["message_valid"],
                true
            );
            encoded.to_owned()
        } else {
            let url = url::Url::parse(outbound["url"].as_str().unwrap()).unwrap();
            let verified = support::bridge_input("verify-saml-redirect",&f._temporary.path().join("state.db"),&serde_json::to_vec(&json!({"query":url.query().unwrap(),"certificate_pem":f.store.active_signing_key(&f.id).unwrap().stored.certificate_pem,"param":"SAMLRequest"})).unwrap());
            assert_eq!(serde_json::from_slice::<Value>(&verified).unwrap(), true);
            url.query_pairs()
                .find(|(key, _)| key == "SAMLRequest")
                .unwrap()
                .1
                .into_owned()
        };
        let xml = decode_message(&encoded).unwrap();
        assert!(xml.contains(session["saml_session_index"].as_str().unwrap()));
        assert!(xml.contains("troy@greendale.edu"));
        let request_id = outbound["request_id"].as_str().unwrap();
        let answer = build_logout_response(
            "urn:greendale:sp",
            &format!("http://{HOST}/saml/greendale/slo"),
            request_id,
            &LogoutStatus::success(),
            Utc::now(),
        );
        let wrong = answer.replace(request_id, "_unknown");
        assert_eq!(
            f.logout_message(&key, binding, "SAMLResponse", &wrong, "")
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            f.admin("/saml/logouts").await["logouts"][0]["outcome"],
            "pending"
        );
        let (status, _, body) = f
            .logout_message(&key, binding, "SAMLResponse", &answer, "")
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert!(
            String::from_utf8(body)
                .unwrap()
                .contains("answered Success")
        );
        let results = f.admin("/saml/logouts").await;
        assert_eq!(results["logouts"][0]["outcome"], "ok");
        assert_eq!(results["logouts"][0]["status"], STATUS_SUCCESS);
        assert!(results["logouts"][0]["answered_at"].is_string());
        assert_eq!(
            f.logout_message(&key, binding, "SAMLResponse", &answer, "")
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            f.send("POST", &path, &input, true, "").await.0,
            StatusCode::NOT_FOUND
        );
    }
}

#[tokio::test]
async fn native_browser_delivery_is_bound_to_the_environment_and_consumed_once() {
    let f = Fixture::new();
    let identity = scimtest_core::oidc::Identity::new(f.store.clone());
    let key = f.store.active_signing_key(&f.id).unwrap();
    let xml = build_logout_response(
        "urn:greendale:idp",
        "https://greendale.example/slo",
        "_study",
        &LogoutStatus::success(),
        Utc::now(),
    );
    let message = encode_logout(
        &key,
        POST_BINDING,
        "SAMLResponse",
        "https://greendale.example/slo",
        xml,
        "study & group",
    )
    .unwrap();
    let ticket = identity.stage_saml_delivery(&f.id, message).unwrap();
    assert!(identity.saml_delivery("city-college", &ticket).is_err());
    assert!(identity.saml_delivery("greendale", "wrong-ticket").is_err());
    let app = api::router_with_identity(
        f.store.clone(),
        "greendale-instance".into(),
        HOST.into(),
        identity.clone(),
    );
    let path = format!("/saml/greendale/continue/{ticket}");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&path)
                .header("Host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let xml = posted_xml(&body);
    assert!(xml.contains("LogoutResponse"));
    assert!(
        String::from_utf8(body.to_vec())
            .unwrap()
            .contains("study &amp; group")
    );
    let response = app
        .oneshot(
            Request::builder()
                .uri(&path)
                .header("Host", HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn saml_logout_notifies_oidc_rps_without_revoking_their_tokens() {
    let f = Fixture::new();
    assert_eq!(
        f.send(
            "PATCH",
            "/api/v1/config",
            &json!({"record_traffic":true}).to_string(),
            true,
            ""
        )
        .await
        .0,
        StatusCode::OK
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<String>(1);
    let app = Router::new().route(
        "/logout",
        axum::routing::post(
            move |axum::Form(values): axum::Form<std::collections::HashMap<String, String>>| {
                let sender = sender.clone();
                async move {
                    sender.send(values["logout_token"].clone()).await.unwrap();
                    StatusCode::OK
                }
            },
        ),
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
    let (cookie, session) = f.saml_session(&f.troy).await;
    let authorize = format!(
        "/oidc/greendale/authorize?{}",
        query(&[
            ("client_id", "greendale".into()),
            ("redirect_uri", CALLBACK.into()),
            ("response_type", "code".into()),
            ("scope", "openid".into()),
            ("prompt", "none".into())
        ])
    );
    let (status, headers, _) = f.send("GET", &authorize, "", false, &cookie).await;
    assert_eq!(status, StatusCode::FOUND);
    let redirect = url::Url::parse(headers["location"].to_str().unwrap()).unwrap();
    let code = redirect
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned();
    let (status, _, body) = f
        .send(
            "POST",
            "/oidc/greendale/token",
            &query(&[
                ("grant_type", "authorization_code".into()),
                ("code", code),
                ("client_id", "greendale".into()),
                ("client_secret", f.secret.clone()),
                ("redirect_uri", CALLBACK.into()),
            ]),
            false,
            "",
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let token: Value = serde_json::from_slice(&body).unwrap();
    let input = json!({"session_id":session["session_id"],"binding":"post"}).to_string();
    assert_eq!(
        f.send(
            "POST",
            &format!("/api/v1/environments/{}/saml/logout", f.id),
            &input,
            true,
            ""
        )
        .await
        .0,
        StatusCode::OK
    );
    let logout_token = tokio::time::timeout(std::time::Duration::from_secs(5), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    let claims = f
        .store
        .active_signing_key(&f.id)
        .unwrap()
        .verify_jwt(&logout_token)
        .unwrap();
    assert_eq!(claims["sid"], session["session_id"]);
    assert!(
        claims["events"]
            .get("http://schemas.openid.net/event/backchannel-logout")
            .is_some()
    );
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oidc/greendale/userinfo")
                .header("Host", HOST)
                .header(
                    "Authorization",
                    format!("Bearer {}", token["access_token"].as_str().unwrap()),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        f.admin("/sessions").await["sessions"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let mut captured = None;
    for _ in 0..50 {
        let (_, _, bytes) = f.send("GET", "/api/v1/traffic", "", false, "").await;
        let traffic: Value = serde_json::from_slice(&bytes).unwrap();
        captured = traffic["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .find(|entry| entry.contains("===== Back-channel logout"))
            .map(str::to_owned);
        if captured.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let captured = captured.expect("backchannel logout transcript");
    assert!(captured.contains("decoded logout_token"));
    assert!(captured.contains(session["session_id"].as_str().unwrap()));
    assert!(!captured.contains(&logout_token));
    server.abort();
}
