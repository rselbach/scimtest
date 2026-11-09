use axum::{
    Router,
    extract::{Request, State},
    http::StatusCode,
    response::IntoResponse,
};
use http_body_util::BodyExt;
use scimtest_core::{
    Store,
    configuration::SettingsPatch,
    model::*,
    scim::{Mode, Service},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone, Default)]
struct Provider(Arc<Mutex<Remote>>);
#[derive(Default)]
struct Remote {
    resources: HashMap<String, Value>,
    requests: Vec<Value>,
    rate_limit: usize,
    retry_after: String,
    filters_unsupported: bool,
    duplicate_match: bool,
    non_advancing: bool,
}
struct Server {
    provider: Provider,
    url: String,
    task: tokio::task::JoinHandle<()>,
}
impl Server {
    async fn new() -> Self {
        let provider = Provider::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(remote).with_state(provider.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            provider,
            url,
            task,
        }
    }
    fn requests(&self) -> Vec<Value> {
        self.provider.0.lock().unwrap().requests.clone()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn remote(State(provider): State<Provider>, request: Request) -> axum::response::Response {
    assert_eq!(request.headers()["Authorization"], "Bearer greendale-scim");
    assert_eq!(request.headers()["Accept"], "application/scim+json");
    let method = request.method().to_string();
    let uri = request.uri().clone();
    let bytes = request.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    let mut state = provider.0.lock().unwrap();
    let mut query = url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    query.sort();
    state
        .requests
        .push(json!({"method":method,"path":uri.path(),"query":query,"body":body}));
    if state.rate_limit > 0 {
        state.rate_limit -= 1;
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", state.retry_after.clone())],
            "Greendale is busy",
        )
            .into_response();
    }
    if uri.path() == "/ServiceProviderConfig" {
        return axum::Json(json!({"patch":{"supported":true},"filter":{"supported":true}}))
            .into_response();
    }
    let collection = if uri.path().starts_with("/Users") {
        "/Users"
    } else {
        "/Groups"
    };
    let key = uri.path().to_owned();
    match method.as_str() {
        "GET" if uri.path() == collection => {
            let filter = query
                .iter()
                .find(|(key, _)| key == "filter")
                .map(|(_, value)| value);
            if filter.is_some() && state.filters_unsupported {
                return (StatusCode::BAD_REQUEST, "filters unsupported").into_response();
            }
            let external = filter
                .and_then(|filter| filter.strip_prefix("externalId eq "))
                .and_then(|value| serde_json::from_str::<String>(value).ok());
            let mut resources = state
                .resources
                .iter()
                .filter(|(path, value)| {
                    path.starts_with(&format!("{collection}/"))
                        && external
                            .as_ref()
                            .is_none_or(|id| value["externalId"] == *id)
                })
                .map(|(_, value)| value.clone())
                .collect::<Vec<_>>();
            resources.sort_by_key(|value| value["id"].as_str().unwrap().to_owned());
            if state.duplicate_match && !resources.is_empty() {
                resources.push(resources[0].clone());
            }
            let total = if state.non_advancing {
                100
            } else {
                resources.len()
            };
            axum::Json(json!({"totalResults":total,"startIndex":1,"Resources":resources}))
                .into_response()
        }
        "GET" => state
            .resources
            .get(&key)
            .map(|value| axum::Json(value.clone()).into_response())
            .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response()),
        "POST" => {
            let mut resource = body;
            let id = format!("remote_{}", resource["externalId"].as_str().unwrap());
            resource["id"] = json!(id);
            state
                .resources
                .insert(format!("{collection}/{id}"), resource.clone());
            (StatusCode::CREATED, axum::Json(resource)).into_response()
        }
        "PUT" => {
            state.resources.insert(key, body);
            StatusCode::NO_CONTENT.into_response()
        }
        "PATCH" => {
            let Some(resource) = state.resources.get_mut(&key) else {
                return StatusCode::NOT_FOUND.into_response();
            };
            for operation in body["Operations"].as_array().unwrap() {
                apply_patch(resource, operation);
            }
            StatusCode::NO_CONTENT.into_response()
        }
        "DELETE" => {
            state.resources.remove(&key);
            StatusCode::NO_CONTENT.into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}
fn apply_patch(resource: &mut Value, operation: &Value) {
    let Some(path) = operation["path"].as_str() else {
        for (key, value) in operation["value"].as_object().unwrap() {
            resource[key] = value.clone();
        }
        return;
    };
    let value = if operation["op"] == "Remove" {
        Value::Null
    } else {
        operation["value"].clone()
    };
    if path == "active" {
        resource["active"] = if value.is_string() {
            json!(value == "True")
        } else {
            value
        };
        return;
    }
    if let Some(name) = path.strip_prefix("name.") {
        resource["name"][name] = value;
        return;
    }
    if path == "emails[type eq \"work\"].value" {
        resource["emails"][0]["value"] = value;
        return;
    }
    if let Some(name) = path.strip_prefix(&format!("{}:", scimtest_core::scim::ENTERPRISE_SCHEMA)) {
        if resource[scimtest_core::scim::ENTERPRISE_SCHEMA].is_null() {
            resource[scimtest_core::scim::ENTERPRISE_SCHEMA] = json!({});
        }
        resource[scimtest_core::scim::ENTERPRISE_SCHEMA][name] =
            if name == "manager" && !value.is_null() {
                json!({"value":value})
            } else {
                value
            };
        return;
    }
    if path == "members" {
        let members = resource["members"].as_array_mut().unwrap();
        let changes = operation["value"].as_array().unwrap();
        if operation["op"] == "Add" {
            members.extend(changes.iter().cloned());
        }
        if operation["op"] == "Remove" {
            members.retain(|member| {
                !changes
                    .iter()
                    .any(|change| change["value"] == member["value"])
            });
        }
        return;
    }
    if value.is_null() {
        resource.as_object_mut().unwrap().remove(path);
    } else {
        resource[path] = value;
    }
}

struct Fixture {
    _temporary: tempfile::TempDir,
    store: Store,
    service: Service,
    id: String,
    troy: String,
    abed: String,
    group: String,
}
impl Fixture {
    fn new(url: &str, persona: &str) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("state.db")).unwrap();
        let environment = store
            .create_environment(EnvironmentInput {
                name: "Greendale".into(),
                settings: SettingsPatch {
                    scim_enabled: Some(true),
                    scim_base_url: Some(url.into()),
                    scim_bearer_token: Some("greendale-scim".into()),
                    persona: Some(persona.into()),
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
                    username: "troy".into(),
                    employee_number: "GCC42".into(),
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
                    username: "abed".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        store
            .update_user(
                &environment.id,
                &troy.id,
                UserPatch {
                    manager_id: Some(abed.id.clone()),
                    ..Default::default()
                },
            )
            .unwrap();
        let group = store
            .create_group(
                &environment.id,
                GroupInput {
                    display_name: "Study Group".into(),
                    member_ids: vec![troy.id.clone(), abed.id.clone()],
                },
            )
            .unwrap();
        let service = Service::new(store.clone());
        Self {
            _temporary: temporary,
            store,
            service,
            id: environment.id,
            troy: troy.id,
            abed: abed.id,
            group: group.id,
        }
    }
    async fn run(&self, mode: Mode) -> scimtest_core::scim::Job {
        self.service.start(&self.id, mode).unwrap();
        self.finish().await
    }
    async fn finish(&self) -> scimtest_core::scim::Job {
        let mut updates = self.service.subscribe();
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                let job = self.service.status(&self.id, 0).unwrap().unwrap();
                if job.is_done() {
                    return job;
                }
                updates.changed().await.unwrap();
            }
        })
        .await
        .unwrap()
    }
}

#[tokio::test]
async fn provisioning_tracks_resources_and_reconciles_remote_changes() {
    let server = Server::new().await;
    let f = Fixture::new(&server.url, "generic");
    let job = f.run(Mode::Sync).await;
    assert!(job.is_success(), "{}", job.message);
    assert_eq!(job.percent, 100);
    let directory = f.store.directory(&f.id).unwrap();
    assert!(
        directory
            .projected_users()
            .iter()
            .all(|user| !user.dirty && !user.remote_id.is_empty())
    );
    assert!(
        directory
            .projected_groups()
            .iter()
            .all(|group| !group.dirty)
    );
    {
        let remote = server.provider.0.lock().unwrap();
        assert_eq!(
            remote.resources[&format!("/Users/remote_{}", f.troy)]
                [scimtest_core::scim::ENTERPRISE_SCHEMA]["manager"]["value"],
            format!("remote_{}", f.abed)
        );
    }
    {
        let mut remote = server.provider.0.lock().unwrap();
        remote
            .resources
            .get_mut(&format!("/Users/remote_{}", f.troy))
            .unwrap()["displayName"] = json!("City College");
        remote
            .resources
            .remove(&format!("/Groups/remote_{}", f.group));
    }
    let job = f.run(Mode::Reconcile).await;
    assert!(job.is_success(), "{}", job.message);
    {
        let remote = server.provider.0.lock().unwrap();
        assert_eq!(
            remote.resources[&format!("/Users/remote_{}", f.troy)]["displayName"],
            "Troy Barnes"
        );
        assert!(
            remote
                .resources
                .contains_key(&format!("/Groups/remote_{}", f.group))
        );
    }
    f.store.delete_user(&f.id, &f.troy).unwrap();
    let job = f.run(Mode::Sync).await;
    assert!(job.is_success(), "{}", job.message);
    let directory = f.store.directory(&f.id).unwrap();
    assert!(!directory.users.iter().any(|user| user.id == f.troy));
    assert_eq!(directory.groups[0].fields.member_ids, vec![f.abed.clone()]);
}

#[tokio::test]
async fn capabilities_and_per_resource_push_preserve_other_pending_work() {
    let server = Server::new().await;
    let f = Fixture::new(&server.url, "generic");
    assert_eq!(
        f.service.discover(f.id.clone(), true).await.unwrap(),
        (true, true)
    );
    assert!(
        f.store
            .directory(&f.id)
            .unwrap()
            .environment
            .settings
            .scim_patch_supported
    );
    let job = f
        .run(Mode::Push {
            resource_type: "user".into(),
            resource_id: f.abed.clone(),
        })
        .await;
    assert!(job.is_success(), "{}", job.message);
    let directory = f.store.directory(&f.id).unwrap();
    let users = directory.projected_users();
    assert!(users.iter().find(|user| user.id == f.troy).unwrap().dirty);
    assert!(!users.iter().find(|user| user.id == f.abed).unwrap().dirty);
    assert!(directory.projected_groups()[0].dirty);
    let job = f.run(Mode::Sync).await;
    assert!(job.is_success(), "{}", job.message);
    f.store
        .update_user(
            &f.id,
            &f.troy,
            UserPatch {
                family_name: Some("Barnes Jr".into()),
                ..Default::default()
            },
        )
        .unwrap();
    let job = f.run(Mode::Sync).await;
    assert!(job.is_success(), "{}", job.message);
    assert!(
        server
            .requests()
            .iter()
            .any(|request| request["method"] == "PATCH"
                && request["body"]["Operations"][0]["value"]["name"]["familyName"] == "Barnes Jr")
    );
}

#[tokio::test]
async fn cancellation_interrupts_rate_limit_waits_and_releases_the_write_guard() {
    use tower::ServiceExt;
    let server = Server::new().await;
    let f = Fixture::new(&server.url, "generic");
    {
        let mut remote = server.provider.0.lock().unwrap();
        remote.rate_limit = 4;
        remote.retry_after = "30".into();
    }
    let mut updates = f.service.subscribe();
    f.service.start(&f.id, Mode::Sync).unwrap();
    let identity = scimtest_core::oidc::Identity::new(f.store.clone());
    let app = scimtest_core::api::router_with_services(
        f.store.clone(),
        "greendale-instance".into(),
        "127.0.0.1:19524".into(),
        identity.clone(),
        f.service.clone(),
    );
    for (method, path, body) in [
        ("PATCH", "/api/v1/config".into(), r#"{"debug":true}"#),
        (
            "PATCH",
            format!("/api/v1/environments/{}", f.id),
            "{malformed",
        ),
        (
            "POST",
            format!("/api/v1/environments/{}/scim/discover", f.id),
            "",
        ),
        (
            "POST",
            format!("/api/v1/environments/{}/restore", f.id),
            "{}",
        ),
        (
            "POST",
            format!("/api/v1/environments/{}/lifecycle/joiner", f.id),
            "{}",
        ),
    ] {
        let request = axum::http::Request::builder()
            .method(method)
            .uri(&path)
            .header("Host", "127.0.0.1:19524")
            .header("X-Scimtest-Instance-Token", "greendale-instance")
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(body))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT, "{path}");
        let body: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(
            body["error"],
            "sync is running; wait for it to finish before changing state"
        );
    }
    assert!(!identity.diagnostics().settings().unwrap().debug);
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("PATCH")
                .uri("/api/v1/traffic/settings")
                .header("Host", "127.0.0.1:19524")
                .header("X-Scimtest-Instance-Token", "greendale-instance")
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(r#"{"record":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(matches!(
        f.store.update_user(
            &f.id,
            &f.troy,
            UserPatch {
                active: Some(false),
                ..Default::default()
            }
        ),
        Err(scimtest_core::Error::Conflict(_))
    ));
    assert!(f.service.start(&f.id, Mode::Sync).is_err());
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if f.service
                .status(&f.id, 0)
                .unwrap()
                .unwrap()
                .is_rate_limited()
            {
                break;
            }
            updates.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    let waiting = serde_json::to_value(f.service.status(&f.id, 0).unwrap().unwrap()).unwrap();
    assert_eq!(waiting["running"], true);
    assert_eq!(waiting["done"], false);
    assert_eq!(waiting["rateLimited"], true);
    f.service.cancel(&f.id).unwrap();
    let job = f.finish().await;
    assert!(!job.is_success());
    assert!(job.error().contains("cancelled"));
    let cancelled = serde_json::to_value(&job).unwrap();
    assert_eq!(cancelled["running"], false);
    assert_eq!(cancelled["done"], true);
    assert_eq!(cancelled["success"], false);
    assert_eq!(cancelled["rateLimited"], false);
    assert_eq!(cancelled["error"], job.error());
    assert!(
        cancelled["finishedAt"]
            .as_str()
            .is_some_and(|at| !at.is_empty())
    );
    f.store
        .update_user(
            &f.id,
            &f.troy,
            UserPatch {
                active: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    let directory = f.store.directory(&f.id).unwrap();
    assert!(directory.projected_users().iter().all(|user| user.dirty));
    assert_eq!(
        f.service.traces(&f.id).unwrap()[0].status,
        "429 Too Many Requests"
    );
    f.service.shutdown().await.unwrap();
}

#[tokio::test]
async fn import_preview_preserves_custom_values_and_rejects_stale_results() {
    let server = Server::new().await;
    let f = Fixture::new(&server.url, "generic");
    assert!(f.run(Mode::Sync).await.is_success());
    f.store
        .update_user(
            &f.id,
            &f.troy,
            UserPatch {
                attributes: Some(std::collections::BTreeMap::from([(
                    "favorite_class".into(),
                    "Air Conditioning Repair".into(),
                )])),
                ..Default::default()
            },
        )
        .unwrap();
    {
        let mut state = server.provider.0.lock().unwrap();
        state.resources.remove(&format!("/Users/remote_{}", f.abed));
        state
            .resources
            .get_mut(&format!("/Users/remote_{}", f.troy))
            .unwrap()["name"]["givenName"] = json!("Troy Updated");
        state
            .resources
            .get_mut(&format!("/Groups/remote_{}", f.group))
            .unwrap()["members"]
            .as_array_mut()
            .unwrap()
            .push(json!({"value":"nested_city_college","type":"Group"}));
    }
    let preview = f.service.preview_import(f.id.clone()).await.unwrap();
    assert_eq!(preview.removed, 1);
    assert_eq!(preview.updated, 2);
    assert!(preview.status.contains("skipped 2 group members"));
    f.store
        .update_user(
            &f.id,
            &f.troy,
            UserPatch {
                active: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(matches!(
        f.service.apply_import(&f.id),
        Err(scimtest_core::Error::Conflict(_))
    ));
    assert!(f.service.import_preview(&f.id).is_err());
    let preview = f.service.preview_import(f.id.clone()).await.unwrap();
    assert_eq!(f.service.apply_import(&f.id).unwrap(), preview.status);
    let directory = f.store.directory(&f.id).unwrap();
    let users = directory.projected_users();
    let troy = users.iter().find(|user| user.id == f.troy).unwrap();
    assert_eq!(troy.fields.given_name, "Troy Updated");
    assert!(troy.fields.active);
    assert_eq!(
        troy.fields.attributes["favorite_class"],
        "Air Conditioning Repair"
    );
    assert!(troy.fields.manager_id.is_empty());
    assert!(!troy.dirty);
    assert!(users.iter().find(|user| user.id == f.abed).unwrap().deleted);
    assert_eq!(directory.groups[0].fields.member_ids, vec![f.troy.clone()]);
    assert!(
        std::fs::read_dir(f._temporary.path().join("backups"))
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("pre-scim-import"))
    );
}

#[tokio::test]
async fn adoption_falls_back_without_filter_support_and_rejects_ambiguous_matches() {
    let server = Server::new().await;
    let f = Fixture::new(&server.url, "generic");
    let directory = f.store.directory(&f.id).unwrap();
    let users = directory.projected_users();
    {
        let mut state = server.provider.0.lock().unwrap();
        state.filters_unsupported = true;
        for user in &users {
            let mut resource = scimtest_core::scim::user_resource(user, &users, true);
            let id = format!("remote_{}", user.id);
            resource["id"] = json!(id);
            state.resources.insert(format!("/Users/{id}"), resource);
        }
    }
    let job = f.run(Mode::Sync).await;
    assert!(job.is_success(), "{}", job.message);
    assert!(job.message.contains("2 adopted"));
    assert!(
        !server
            .requests()
            .iter()
            .any(|request| request["method"] == "POST" && request["path"] == "/Users")
    );
    f.store.reset_scim(&f.id).unwrap();
    {
        let mut state = server.provider.0.lock().unwrap();
        state.filters_unsupported = false;
        state.duplicate_match = true;
        state.requests.clear();
    }
    let job = f.run(Mode::Sync).await;
    assert!(!job.is_success());
    assert!(
        f.store
            .directory(&f.id)
            .unwrap()
            .projected_users()
            .iter()
            .all(|user| user.dirty)
    );
    assert!(
        !server
            .requests()
            .iter()
            .any(|request| request["method"] == "POST")
    );
    assert!(
        f.service
            .traces(&f.id)
            .unwrap()
            .iter()
            .any(|trace| trace.err.contains("multiple resources"))
    );
}

#[tokio::test]
async fn pagination_loops_and_long_rate_limits_stop_without_writing_remote_data() {
    let server = Server::new().await;
    let f = Fixture::new(&server.url, "generic");
    {
        let mut remote = server.provider.0.lock().unwrap();
        remote.non_advancing = true;
        remote.resources.insert(
            "/Users/remote_troy".into(),
            json!({"id":"remote_troy","externalId":"user_troy","userName":"troy"}),
        );
    }
    let mut client = scimtest_core::scim::Client::new(
        f.store.directory(&f.id).unwrap().environment.settings,
        Default::default(),
    )
    .unwrap();
    let error = client.list("/Users", "user", "import").await.unwrap_err();
    assert!(error.to_string().contains("did not advance"));
    {
        let mut remote = server.provider.0.lock().unwrap();
        remote.rate_limit = 1;
        remote.retry_after = "31".into();
        remote.requests.clear();
    }
    let job = tokio::time::timeout(std::time::Duration::from_secs(2), f.run(Mode::Sync))
        .await
        .unwrap();
    assert!(!job.is_success());
    assert_eq!(server.requests().len(), 1);
    assert!(job.error().contains("31 seconds"));
}

#[tokio::test]
async fn management_api_exposes_scim_jobs_plans_and_import_previews() {
    use tower::ServiceExt;
    const HOST: &str = "127.0.0.1:19524";
    let server = Server::new().await;
    let f = Fixture::new(&server.url, "generic");
    let app = scimtest_core::api::router_with_services(
        f.store.clone(),
        "greendale-instance".into(),
        HOST.into(),
        scimtest_core::oidc::Identity::new(f.store.clone()),
        f.service.clone(),
    );
    let request = |method: &str, suffix: &str| {
        axum::http::Request::builder()
            .method(method)
            .uri(format!("/api/v1/environments/{}{suffix}", f.id))
            .header("Host", HOST)
            .header("X-Scimtest-Instance-Token", "greendale-instance")
            .body(axum::body::Body::empty())
            .unwrap()
    };
    let response = app
        .clone()
        .oneshot(request("GET", "/sync/plan"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let plan: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(plan["entries"].as_array().unwrap().len(), 3);
    assert!(
        plan["summary"]
            .as_str()
            .unwrap()
            .contains("create user Troy Barnes")
    );
    let response = app
        .clone()
        .oneshot(request("POST", "/sync/start"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let started: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(started["running"], true);
    assert_eq!(started["done"], false);
    assert_eq!(started["success"], false);
    assert_eq!(started["rateLimited"], false);
    assert_eq!(started["error"], "");
    assert!(started.get("finishedAt").is_none());
    let job = f.finish().await;
    assert!(job.is_success());
    let response = app
        .clone()
        .oneshot(request("GET", "/sync/status?after=2"))
        .await
        .unwrap();
    let value: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(value["done"], true);
    assert_eq!(value["running"], false);
    assert_eq!(value["success"], true);
    assert_eq!(value["rateLimited"], false);
    assert_eq!(value["error"], "");
    assert!(
        value["finishedAt"]
            .as_str()
            .is_some_and(|at| !at.is_empty())
    );
    assert_eq!(value["traceAvailable"], true);
    assert!(
        value["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|event| event["sequence"].as_u64().unwrap() > 2)
    );
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "/sync/status?after=-1"))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        app.clone()
            .oneshot(request("POST", "/import/preview"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let response = app
        .clone()
        .oneshot(request("GET", "/import/preview"))
        .await
        .unwrap();
    let preview: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(preview["digest"].as_str().unwrap().len(), 64);
    assert_eq!(preview["removed"], 0);
    assert_eq!(
        app.clone()
            .oneshot(request("POST", "/import/apply"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(request("GET", "/import/preview"))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.clone()
            .oneshot(request("POST", "/scim/discover"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.oneshot(request("POST", "/sync/cancel"))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn entra_adoption_uses_path_patches_and_title_case_booleans() {
    let server = Server::new().await;
    let f = Fixture::new(&server.url, "entra");
    let directory = f.store.directory(&f.id).unwrap();
    let users = directory.projected_users();
    let mut seeded = HashMap::new();
    for user in &users {
        let mut resource = scimtest_core::scim::user_resource(user, &users, true);
        let id = format!("remote_{}", user.id);
        resource["id"] = json!(id);
        resource["active"] = json!(false);
        resource["name"]["givenName"] = json!("City College");
        seeded.insert(format!("/Users/{id}"), resource);
    }
    let mut group = json!({"id":format!("remote_{}",f.group),"externalId":f.group,"displayName":"City College","members":[]});
    group["schemas"] = json!([scimtest_core::scim::GROUP_SCHEMA]);
    seeded.insert(format!("/Groups/remote_{}", f.group), group);
    server.provider.0.lock().unwrap().resources = seeded;
    let job = f.run(Mode::Sync).await;
    assert!(job.is_success(), "{}", job.message);
    let requests = server.requests();
    assert!(
        requests
            .iter()
            .filter(|request| request["method"] == "GET")
            .all(|request| !request["query"]
                .as_array()
                .unwrap()
                .iter()
                .any(|pair| pair[0] == "count"))
    );
    assert!(requests.iter().any(|request| {
        request["method"] == "PATCH"
            && request["body"]["Operations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|operation| operation["path"] == "active" && operation["value"] == "True")
    }));
}

#[tokio::test]
async fn malformed_remote_attributes_fail_without_overwriting_the_directory() {
    let server = Server::new().await;
    let f = Fixture::new(&server.url, "generic");
    server.provider.0.lock().unwrap().resources.insert(
        "/Users/remote_troy".into(),
        json!({"id":"remote_troy","externalId":"user_troy","userName":"troy","active":"true"}),
    );
    let error = f.service.preview_import(f.id.clone()).await.unwrap_err();
    assert!(error.to_string().contains("active must be a boolean"));
    assert_eq!(f.store.directory(&f.id).unwrap().users.len(), 2);
    assert!(
        f.service
            .traces(&f.id)
            .unwrap()
            .iter()
            .any(|trace| trace.err.contains("active must be a boolean"))
    );
}
