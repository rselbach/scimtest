#[path = "lifecycle/target.rs"]
mod target;
use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use scimtest_core::{
    Store, api,
    configuration::SettingsPatch,
    model::*,
    oidc::{Identity, object_id},
    scim::{Mode, Service},
};
use serde_json::{Value, json};
use target::Target;
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:19528";
const TOKEN: &str = "greendale-instance";
const CALLBACK: &str = "https://greendale.example/callback";
struct Fixture {
    _temporary: tempfile::TempDir,
    store: Store,
    identity: Identity,
    scim: Service,
    app: Router,
    id: String,
    troy: String,
    pierce: String,
    study: String,
    glee: String,
    secret: String,
}
impl Fixture {
    fn new(target: Option<&Target>) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("state.db")).unwrap();
        let environment = store
            .create_environment(EnvironmentInput {
                name: "Greendale".into(),
                settings: SettingsPatch {
                    oidc_enabled: Some(true),
                    oidc_client_id: Some("greendale".into()),
                    oidc_redirect_uris: Some(vec![CALLBACK.into()]),
                    oidc_backchannel_logout_uri: target
                        .map(|target| format!("{}/backchannel", target.url)),
                    oidc_backchannel_logout_session_required: Some(true),
                    saml_enabled: Some(true),
                    saml_acs_url: Some("https://greendale.example/acs".into()),
                    saml_entity_id: Some("urn:greendale:sp".into()),
                    saml_slo_url: Some("https://greendale.example/slo".into()),
                    include_groups_claim: Some(true),
                    scim_enabled: Some(target.is_some()),
                    scim_base_url: target.map(|target| target.url.clone()),
                    scim_bearer_token: target.map(|_| "greendale-scim".into()),
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
        let pierce = store
            .create_user(
                &environment.id,
                UserInput {
                    given_name: "Pierce".into(),
                    family_name: "Hawthorne".into(),
                    email: "pierce@greendale.edu".into(),
                    active: false,
                    ..Default::default()
                },
            )
            .unwrap();
        let study = store
            .create_group(
                &environment.id,
                GroupInput {
                    display_name: "Study Group".into(),
                    member_ids: vec![troy.id.clone()],
                },
            )
            .unwrap();
        let glee = store
            .create_group(
                &environment.id,
                GroupInput {
                    display_name: "Glee Club".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        let identity = Identity::new(store.clone());
        let scim = Service::new(store.clone());
        let app = api::router_with_services(
            store.clone(),
            TOKEN.into(),
            HOST.into(),
            identity.clone(),
            scim.clone(),
        );
        Self {
            _temporary: temporary,
            store,
            identity,
            scim,
            app,
            id: environment.id,
            troy: troy.id,
            pierce: pierce.id,
            study: study.id,
            glee: glee.id,
            secret: environment.settings.oidc_client_secret,
        }
    }
    fn configure(&self, value: Value) {
        self.store
            .update_environment(
                &self.id,
                EnvironmentPatch {
                    settings: serde_json::from_value(value).unwrap(),
                    ..Default::default()
                },
            )
            .unwrap();
    }
    async fn send(
        &self,
        method: &str,
        path: &str,
        body: &str,
        cookie: &str,
        bearer: &str,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("Host", HOST)
            .header("X-Scimtest-Instance-Token", TOKEN)
            .header(
                "Content-Type",
                if path.starts_with("/api/") || path.ends_with("/getMemberObjects") {
                    "application/json"
                } else {
                    "application/x-www-form-urlencoded"
                },
            )
            .header("Cookie", cookie)
            .header(
                "Authorization",
                if bearer.is_empty() {
                    String::new()
                } else {
                    format!("Bearer {bearer}")
                },
            )
            .body(Body::from(body.to_owned()))
            .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
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
    async fn admin(&self, method: &str, suffix: &str, body: Value) -> (StatusCode, Value) {
        let (status, _, bytes) = self
            .send(
                method,
                &format!("/api/v1/environments/{}{}", self.id, suffix),
                &body.to_string(),
                "",
                "",
            )
            .await;
        (status, serde_json::from_slice(&bytes).unwrap())
    }
    async fn start(&self, kind: &str, body: Value) -> Value {
        let (status, run) = self
            .admin("POST", &format!("/lifecycle/{kind}"), body)
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{run}");
        run
    }
    async fn run(&self, id: &str) -> Value {
        let (status, run) = self
            .admin("GET", &format!("/lifecycle/{id}"), json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "{run}");
        run
    }
    async fn settled(&self, id: &str) -> Value {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let run = self.run(id).await;
                if run["status"] != "running" {
                    break run;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }
    async fn provision(&self) {
        self.scim.start(&self.id, Mode::Sync).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let job = self.scim.status(&self.id, 0).unwrap().unwrap();
                if job.done {
                    assert!(job.success, "{}", job.message);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
    async fn oidc(&self, scope: &str) -> (String, Value) {
        let path = format!("/api/v1/environments/{}/oidc/authorize", self.id);
        let (status, headers, body) = self
            .send(
                "POST",
                &path,
                &json!({"user_id":self.troy,"redirect_uri":CALLBACK,"scope":scope}).to_string(),
                "",
                "",
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let code: Value = serde_json::from_slice(&body).unwrap();
        let cookie = headers["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let form = serde_urlencoded::to_string([
            ("grant_type", "authorization_code"),
            ("code", code["code"].as_str().unwrap()),
            ("client_id", "greendale"),
            ("client_secret", &self.secret),
            ("redirect_uri", CALLBACK),
        ])
        .unwrap();
        let (status, _, body) = self
            .send("POST", "/oidc/greendale/token", &form, "", "")
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        (cookie, serde_json::from_slice(&body).unwrap())
    }
    async fn saml(&self, cookie: &str) {
        let form = serde_urlencoded::to_string([("user_id", self.troy.as_str())]).unwrap();
        let (status, _, body) = self
            .send("POST", "/saml/greendale/sso", &form, cookie, "")
            .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    }
}
impl Fixture {
    async fn answer_logout(&self, request_id: &str) -> StatusCode {
        let xml = scimtest_core::saml::build_logout_response(
            "urn:greendale:sp",
            &format!("http://{HOST}/saml/greendale/slo"),
            request_id,
            &scimtest_core::saml::LogoutStatus {
                code: scimtest_core::saml::STATUS_SUCCESS.into(),
                subcode: String::new(),
                message: String::new(),
            },
            chrono::Utc::now(),
        );
        let form = serde_urlencoded::to_string([("SAMLResponse", STANDARD.encode(xml))]).unwrap();
        self.send("POST", "/saml/greendale/slo", &form, "", "")
            .await
            .0
    }
}
fn step<'a>(run: &'a Value, id: &str) -> &'a Value {
    run["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["id"] == id)
        .unwrap()
}
fn run_id(run: &Value) -> &str {
    run["id"].as_str().unwrap()
}

#[tokio::test]
async fn rejected_lifecycle_requests_preserve_the_directory_and_do_not_create_runs() {
    let f = Fixture::new(None);
    let before = serde_json::to_value(f.store.directory(&f.id).unwrap()).unwrap();
    for (path, body, status, message) in [
        (
            "/lifecycle/leaver",
            json!({"user_id":"user_chang"}),
            StatusCode::NOT_FOUND,
            "user \"user_chang\" not found",
        ),
        (
            "/lifecycle/mover",
            json!({"user_id":f.troy}),
            StatusCode::BAD_REQUEST,
            "choose at least one group to add or remove",
        ),
        (
            "/lifecycle/mover",
            json!({"user_id":f.troy,"add_group_ids":[f.study]}),
            StatusCode::BAD_REQUEST,
            "Troy Barnes is already in Study Group",
        ),
        (
            "/lifecycle/mover",
            json!({"user_id":f.troy,"remove_group_ids":[f.glee]}),
            StatusCode::BAD_REQUEST,
            "Troy Barnes is not in Glee Club",
        ),
        (
            "/lifecycle/mover",
            json!({"user_id":f.pierce,"add_group_ids":[f.glee]}),
            StatusCode::BAD_REQUEST,
            "Pierce Hawthorne is inactive; activate the user before moving them",
        ),
        (
            "/lifecycle/mover",
            json!({"user_id":f.troy,"add_group_ids":[f.glee,f.glee]}),
            StatusCode::BAD_REQUEST,
            "group Glee Club is listed more than once",
        ),
        (
            "/lifecycle/joiner",
            json!({"given_name":"Britta","email":"britta@greendale.edu","group_ids":["group_chang"]}),
            StatusCode::NOT_FOUND,
            "group \"group_chang\" not found",
        ),
    ] {
        let (got, value) = f.admin("POST", path, body).await;
        assert_eq!(got, status, "{value}");
        assert_eq!(value["error"], message);
        assert_eq!(
            serde_json::to_value(f.store.directory(&f.id).unwrap()).unwrap(),
            before
        );
        assert!(f.identity.lifecycle_runs(&f.id).unwrap().is_empty());
    }
    assert_eq!(
        f.admin("GET", "/lifecycle/missing", json!({})).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn failed_dependencies_are_skipped_while_independent_pushes_and_logouts_continue() {
    let target = Target::new().await;
    let f = Fixture::new(Some(&target));
    f.provision().await;
    target.fail("POST", "/Users", StatusCode::BAD_REQUEST);
    let run = f
        .start(
            "joiner",
            json!({"given_name":"Britta","email":"britta@greendale.edu","group_ids":[f.study]}),
        )
        .await;
    let run = f.settled(run_id(&run)).await;
    assert_eq!(run["status"], "failed");
    assert_eq!(step(&run, "scim-user")["status"], "failed");
    assert_eq!(
        step(&run, &format!("scim-group-{}", f.study))["status"],
        "skipped"
    );
    target.fail("PUT", "/Groups", StatusCode::BAD_REQUEST);
    let run = f
        .start(
            "mover",
            json!({"user_id":f.troy,"add_group_ids":[f.glee],"remove_group_ids":[f.study]}),
        )
        .await;
    let run = f.settled(run_id(&run)).await;
    for group in [&f.study, &f.glee] {
        let step = step(&run, &format!("scim-group-{group}"));
        assert_eq!(step["status"], "failed", "{run}");
        if group == &f.glee {
            assert_eq!(step["messages"][0]["outcome"], "failed");
        }
    }
    target.fail("POST", "/backchannel", StatusCode::SERVICE_UNAVAILABLE);
    let (cookie, _) = f.oidc("openid groups").await;
    f.saml(&cookie).await;
    let run = f.start("leaver", json!({"user_id":f.troy})).await;
    let run = f.settled(run_id(&run)).await;
    assert_eq!(run["status"], "failed");
    assert_eq!(step(&run, "scim-user")["status"], "ok");
    assert_eq!(
        step(
            &run,
            &format!("backchannel-{}", cookie.split_once('=').unwrap().1)
        )["status"],
        "failed"
    );
}

#[tokio::test]
async fn skipped_protocols_inactive_leavers_and_bounded_runs_match_the_go_contract() {
    let f = Fixture::new(None);
    f.configure(json!({"oidc_enabled":false,"saml_enabled":false}));
    let run = f.start("leaver", json!({"user_id":f.pierce})).await;
    assert_eq!(run["status"], "ok");
    for id in [
        "deactivate",
        "sessions",
        "backchannel",
        "saml-logout",
        "revoke",
        "scim",
    ] {
        assert_eq!(step(&run, id)["status"], "skipped", "{run}");
    }
    assert_eq!(
        step(&run, "deactivate")["detail"],
        "Pierce Hawthorne was already inactive"
    );
    assert_eq!(
        step(&run, "sessions")["detail"],
        "The environment has no OIDC or SAML configuration"
    );
    for _ in 0..11 {
        f.start("leaver", json!({"user_id":f.pierce})).await;
    }
    let (_, runs) = f.admin("GET", "/lifecycle", json!({})).await;
    assert_eq!(runs["runs"].as_array().unwrap().len(), 10);
    assert!(
        !runs["runs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|current| current["id"] == run["id"])
    );
    let other = f
        .store
        .create_environment(EnvironmentInput {
            name: "City College".into(),
            ..Default::default()
        })
        .unwrap();
    assert!(f.identity.lifecycle_runs(&other.id).unwrap().is_empty());
    assert!(
        Identity::new(f.store.clone())
            .lifecycle_runs(&f.id)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn mover_accepts_okta_everyone_and_reads_each_saml_signing_mode_and_encryption() {
    for mode in ["assertion", "response", "both", "encrypted"] {
        let f = Fixture::new(None);
        f.configure(json!({"persona":"okta","saml_signing_mode":if mode == "encrypted" { "both" } else { mode }}));
        if mode == "encrypted" {
            let certificate = f.store.shared_signing_key().unwrap().stored.certificate_pem;
            f.configure(json!({"saml_encryption_certificate_pem":certificate}));
        }
        let run = f
            .start(
                "mover",
                json!({"user_id":f.troy,"add_group_ids":[f.glee],"remove_group_ids":[f.study]}),
            )
            .await;
        let (cookie, _) = f.oidc("openid groups").await;
        f.saml(&cookie).await;
        let run = f.run(run_id(&run)).await;
        assert_eq!(run["status"], "ok", "{mode}: {run}");
        assert!(
            step(&run, "oidc-groups")["detail"]
                .as_str()
                .unwrap()
                .contains("Everyone")
        );
        assert_eq!(
            step(&run, "saml-groups")["detail"],
            "The SAML assertion carried the new groups: Glee Club"
        );
    }
}

#[tokio::test]
async fn mover_checks_userinfo_and_faulted_claims_instead_of_the_directory_alone() {
    let f = Fixture::new(None);
    let (_, tokens) = f.oidc("openid groups").await;
    let run = f
        .start(
            "mover",
            json!({"user_id":f.troy,"add_group_ids":[f.glee],"remove_group_ids":[f.study]}),
        )
        .await;
    assert_eq!(
        f.send(
            "GET",
            "/oidc/greendale/userinfo",
            "",
            "",
            tokens["access_token"].as_str().unwrap()
        )
        .await
        .0,
        StatusCode::OK
    );
    let run = f.run(run_id(&run)).await;
    assert_eq!(
        step(&run, "oidc-groups")["detail"],
        "The userinfo response carried the new groups: Glee Club"
    );
    let run = f
        .start(
            "mover",
            json!({"user_id":f.troy,"add_group_ids":[f.study],"remove_group_ids":[f.glee]}),
        )
        .await;
    f.identity
        .arm_faults(
            &f.id,
            scimtest_core::oidc::Faults {
                drop_claims: vec!["groups".into()],
                ..Default::default()
            },
        )
        .unwrap();
    let (cookie, _) = f.oidc("openid groups").await;
    assert_eq!(
        step(&f.run(run_id(&run)).await, "oidc-groups")["status"],
        "failed"
    );
    f.identity
        .arm_faults(
            &f.id,
            scimtest_core::oidc::Faults {
                saml_status: "AuthnFailed".into(),
                ..Default::default()
            },
        )
        .unwrap();
    f.saml(&cookie).await;
    assert_eq!(
        step(&f.run(run_id(&run)).await, "saml-groups")["status"],
        "waiting"
    );
    f.saml(&cookie).await;
    assert_eq!(
        step(&f.run(run_id(&run)).await, "saml-groups")["status"],
        "ok"
    );
}

#[tokio::test]
async fn lifecycle_saml_post_is_signed_retries_and_correlates_only_the_latest_request() {
    let f = Fixture::new(None);
    let (cookie, _) = f.oidc("openid").await;
    f.saml(&cookie).await;
    let run = f.start("leaver", json!({"user_id":f.troy})).await;
    let step_id = format!("saml-logout-{}", cookie.split_once('=').unwrap().1);
    let path = "/inspect/lifecycle/greendale/saml-logout";
    let form = serde_urlencoded::to_string([
        ("run_id", run_id(&run)),
        ("step_id", &step_id),
        ("binding", "post"),
    ])
    .unwrap();
    let (status, _, body) = f.send("POST", path, &form, "", "").await;
    assert_eq!(status, StatusCode::OK);
    let html = String::from_utf8(body).unwrap();
    let response = regex::Regex::new(r#"name="SAMLRequest" value="([^"]+)""#)
        .unwrap()
        .captures(&html)
        .unwrap()[1]
        .to_owned();
    let xml = String::from_utf8(STANDARD.decode(response).unwrap()).unwrap();
    scimtest_core::saml::verify_xml(
        &xml,
        &f.store
            .active_signing_key(&f.id)
            .unwrap()
            .stored
            .certificate_pem,
        "LogoutRequest",
    )
    .unwrap();
    let first = f.run(run_id(&run)).await;
    assert_eq!(step(&first, &step_id)["status"], "waiting");
    assert!(step(&first, &step_id).get("browser_url").is_none());
    let (status, _, body) = f.send("POST", path, &form, "", "").await;
    assert_eq!(status, StatusCode::OK);
    let retried = f.run(run_id(&run)).await;
    assert_eq!(
        step(&retried, &step_id)["messages"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_ne!(
        step(&retried, &step_id)["messages"][0]["sent"],
        step(&retried, &step_id)["messages"][1]["sent"]
    );
    let response = f
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("Host", HOST)
                .header("Origin", "https://citycollege.example")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        step(&f.run(run_id(&run)).await, &step_id)["messages"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let first = bergshamra::xml::uppsala::parse(&xml).unwrap();
    let first_id = first
        .element(first.document_element().unwrap())
        .unwrap()
        .get_attribute("ID")
        .unwrap();
    assert_eq!(f.answer_logout(first_id).await, StatusCode::OK);
    assert_eq!(
        step(&f.run(run_id(&run)).await, &step_id)["status"],
        "waiting"
    );
    let html = String::from_utf8(body).unwrap();
    let encoded = regex::Regex::new(r#"name="SAMLRequest" value="([^"]+)""#)
        .unwrap()
        .captures(&html)
        .unwrap()[1]
        .to_owned();
    let xml = String::from_utf8(STANDARD.decode(encoded).unwrap()).unwrap();
    let second = bergshamra::xml::uppsala::parse(&xml).unwrap();
    let second_id = second
        .element(second.document_element().unwrap())
        .unwrap()
        .get_attribute("ID")
        .unwrap();
    assert_eq!(f.answer_logout(second_id).await, StatusCode::OK);
    assert_eq!(f.run(run_id(&run)).await["status"], "ok");
}

#[tokio::test]
async fn joiner_provisions_the_user_before_group_membership_and_records_messages() {
    let target = Target::new().await;
    let f = Fixture::new(Some(&target));
    f.provision().await;
    let run = f.start("joiner",json!({"given_name":"Britta","family_name":"Perry","email":"britta@greendale.edu","group_ids":[f.study]})).await;
    let run = f.settled(run_id(&run)).await;
    assert_eq!(run["status"], "ok", "{run}");
    assert_eq!(run["user"], "Britta Perry");
    assert_eq!(step(&run, "groups")["detail"], "Added to Study Group");
    let id = run["user_id"].as_str().unwrap();
    let directory = f.store.directory(&f.id).unwrap();
    let remote = &directory.user_sync[id].remote_id;
    assert_eq!(
        target.resource(&format!("/Users/{remote}"))["userName"],
        "britta@greendale.edu"
    );
    assert_eq!(
        step(&run, "scim-user")["messages"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()["sent"],
        "POST /Users"
    );
    let group = &directory.group_sync[&f.study].remote_id;
    assert!(
        target.resource(&format!("/Groups/{group}"))["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member["value"] == *remote)
    );
    assert_eq!(
        step(&run, &format!("scim-group-{}", f.study))["status"],
        "ok"
    );
}

#[tokio::test]
async fn mover_pushes_both_groups_then_checks_the_next_id_token_and_assertion() {
    let target = Target::new().await;
    let f = Fixture::new(Some(&target));
    f.provision().await;
    let run = f
        .start(
            "mover",
            json!({"user_id":f.troy,"add_group_ids":[f.glee],"remove_group_ids":[f.study]}),
        )
        .await;
    let run = f.settled(run_id(&run)).await;
    assert_eq!(run["status"], "waiting");
    assert_eq!(
        step(&run, "groups")["detail"],
        "Added to Glee Club; removed from Study Group"
    );
    for group in [&f.study, &f.glee] {
        assert_eq!(
            step(&run, &format!("scim-group-{group}"))["status"],
            "ok",
            "{run}"
        );
    }
    let (cookie, _) = f.oidc("openid email groups").await;
    f.saml(&cookie).await;
    let run = f.run(run_id(&run)).await;
    assert_eq!(run["status"], "ok", "{run}");
    assert_eq!(
        step(&run, "oidc-groups")["detail"],
        "The ID token carried the new groups: Glee Club"
    );
    assert_eq!(
        step(&run, "saml-groups")["detail"],
        "The SAML assertion carried the new groups: Glee Club"
    );
}

#[tokio::test]
async fn missing_groups_fail_and_entra_overage_waits_for_the_actual_source_response() {
    let f = Fixture::new(None);
    let run = f
        .start("mover", json!({"user_id":f.troy,"add_group_ids":[f.glee]}))
        .await;
    f.oidc("openid email").await;
    let run = f.run(run_id(&run)).await;
    assert_eq!(step(&run, "oidc-groups")["status"], "failed");
    assert_eq!(
        step(&run, "oidc-groups")["detail"],
        "The ID token carried no groups"
    );
    f.configure(json!({"persona":"entra","groups_overage_threshold":1,"oidc_claim_mappings":{"groups":"study_groups"}}));
    f.start(
        "mover",
        json!({"user_id":f.troy,"remove_group_ids":[f.glee]}),
    )
    .await;
    let run = f
        .start("mover", json!({"user_id":f.troy,"add_group_ids":[f.glee]}))
        .await;
    let (cookie, tokens) = f.oidc("openid groups").await;
    let current = f.run(run_id(&run)).await;
    assert_eq!(
        step(&current, "oidc-groups")["status"],
        "waiting",
        "{current}"
    );
    assert_eq!(
        step(&current, "oidc-groups")["messages"][0]["body"],
        "groups overage"
    );
    let access = tokens["access_token"].as_str().unwrap();
    assert_eq!(
        f.send(
            "POST",
            &format!(
                "/oidc/greendale/users/{}/getMemberObjects",
                object_id(&f.id, &f.troy)
            ),
            r#"{"securityEnabledOnly":false}"#,
            "",
            access
        )
        .await
        .0,
        StatusCode::OK
    );
    f.saml(&cookie).await;
    assert_eq!(f.run(run_id(&run)).await["status"], "ok");
}

#[tokio::test]
async fn leaver_ends_shared_sessions_delivers_logout_revokes_tokens_and_finishes_saml_in_a_browser()
{
    let target = Target::new().await;
    let f = Fixture::new(Some(&target));
    f.provision().await;
    let (cookie, tokens) = f.oidc("openid groups").await;
    f.saml(&cookie).await;
    let session = cookie.split_once('=').unwrap().1;
    let run = f.start("leaver", json!({"user_id":f.troy})).await;
    let run = f.settled(run_id(&run)).await;
    assert_eq!(run["status"], "waiting", "{run}");
    assert_eq!(
        step(&run, &format!("backchannel-{session}"))["status"],
        "ok"
    );
    assert_eq!(step(&run, "revoke")["detail"], "Revoked 1 tokens");
    assert!(f.identity.sessions(&f.id).unwrap().is_empty());
    assert_eq!(
        f.send(
            "GET",
            "/oidc/greendale/userinfo",
            "",
            "",
            tokens["access_token"].as_str().unwrap()
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let directory = f.store.directory(&f.id).unwrap();
    let remote = &directory.user_sync[&f.troy].remote_id;
    assert_eq!(
        target.resource(&format!("/Users/{remote}"))["active"],
        false
    );
    let token = target.data.lock().unwrap().logout_tokens[0].clone();
    assert_eq!(
        f.store
            .active_signing_key(&f.id)
            .unwrap()
            .verify_jwt(&token)
            .unwrap()["sid"],
        session
    );
    let saml_step = format!("saml-logout-{session}");
    assert_eq!(step(&run, &saml_step)["status"], "needs_browser");
    assert_eq!(
        step(&run, &saml_step)["browser_url"],
        format!(
            "http://{HOST}/?environment={}&tab=lifecycle#lifecycle-run-{}",
            f.id,
            run_id(&run)
        )
    );
    let (status, _, html) = f
        .send(
            "GET",
            &format!("/?environment={}&tab=lifecycle", f.id),
            "",
            "",
            "",
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        String::from_utf8(html)
            .unwrap()
            .contains("Send LogoutRequest")
    );
    let form = serde_urlencoded::to_string([
        ("run_id", run_id(&run)),
        ("step_id", &saml_step),
        ("binding", "redirect"),
    ])
    .unwrap();
    let (status, headers, _) = f
        .send(
            "POST",
            "/inspect/lifecycle/greendale/saml-logout",
            &form,
            "",
            "",
        )
        .await;
    assert_eq!(status, StatusCode::FOUND);
    let location = url::Url::parse(headers["location"].to_str().unwrap()).unwrap();
    let query = location
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    let request = scimtest_core::saml::decode_message(&query["SAMLRequest"]).unwrap();
    let document = bergshamra::xml::uppsala::parse(&request).unwrap();
    let root = document.document_element().unwrap();
    let request_id = document.element(root).unwrap().get_attribute("ID").unwrap();
    let xml = scimtest_core::saml::build_logout_response(
        "urn:greendale:sp",
        &format!("http://{HOST}/saml/greendale/slo"),
        request_id,
        &scimtest_core::saml::LogoutStatus {
            code: scimtest_core::saml::STATUS_SUCCESS.into(),
            subcode: String::new(),
            message: String::new(),
        },
        chrono::Utc::now(),
    );
    let form = serde_urlencoded::to_string([("SAMLResponse", STANDARD.encode(xml))]).unwrap();
    assert_eq!(
        f.send("POST", "/saml/greendale/slo", &form, "", "").await.0,
        StatusCode::OK
    );
    let run = f.run(run_id(&run)).await;
    assert_eq!(run["status"], "ok", "{run}");
    assert_eq!(
        step(&run, &saml_step)["messages"][0]["response"],
        "LogoutResponse: the SP answered Success"
    );
}
