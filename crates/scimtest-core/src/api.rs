mod account;
mod authorize;
mod chooser;
mod identity;
use authorize::authorize;
mod keys;
mod lifecycle;
mod oidc;
mod playground;
mod request;
mod saml;
mod scenarios;
mod scim;
mod traffic;
use account::{account, account_logout, account_retry, account_start, tunnel, tunnel_retry};
use identity::{
    end_sessions, fault_delete, fault_get, fault_put, flows, inspections, oidc_tokens, playground,
    revoke_oidc_tokens, sessions,
};
use keys::{connection, rotate_key, signing_keys};
use lifecycle::{
    get_run as lifecycle_get, joiner as lifecycle_joiner, leaver as lifecycle_leaver,
    list as lifecycle_list, mover as lifecycle_mover,
};
use request::{authenticate, validate_body};
use saml::{logout as saml_logout, logouts as saml_logouts, sign_in as saml_sign_in};
use scenarios::{arm as scenarios_arm, disarm as scenarios_disarm, get as scenarios_get};
use scim::{
    cancel as sync_cancel, discover as scim_discover, plan as sync_plan, push_group, push_user,
    reconcile, reset as sync_reset, status as sync_status, sync as sync_start, test as scim_test,
    trace as sync_trace,
};
use scim::{import_apply, import_preview, import_preview_get};
use traffic::{clear as traffic_clear, settings as traffic_settings, snapshot as traffic_snapshot};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, MatchedPath, Path, Request, State, rejection::JsonRejection},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{
    Error, Store,
    backup::StateBackup,
    configuration::{GlobalConfig, GlobalConfigPatch, SettingsPatch},
    model::*,
};

#[derive(Clone)]
struct ApiState {
    store: Store,
    identity: crate::oidc::Identity,
    scim: crate::scim::Service,
    tunnel: crate::tunnel::Service,
    tunneled: bool,
    token: String,
    host: String,
    diagnostics: crate::diagnostics::Diagnostics,
    activation: Option<tokio::sync::watch::Sender<u64>>,
}

pub fn public_router(
    store: Store,
    host: String,
    identity: crate::oidc::Identity,
    scim: crate::scim::Service,
    tunnel: crate::tunnel::Service,
) -> Router {
    let diagnostics = identity.diagnostics();
    let state = ApiState {
        store,
        host,
        identity,
        scim,
        tunnel,
        tunneled: true,
        token: String::new(),
        diagnostics,
        activation: None,
    };
    let protocols = oidc::router(state.clone()).merge(saml::router(state.clone()));
    Router::new()
        .fallback_service(protocols)
        .layer(middleware::from_fn_with_state(
            state,
            account::public_boundary,
        ))
}

macro_rules! api_routes {
    ($($method:ident $path:literal, $fields:expr => $handler:ident, $mutates:literal;)+) => {
        pub fn router(store: Store, token: String, host: String) -> Router {
            let identity = crate::oidc::Identity::new(store.clone());
            router_with_identity(store, token, host, identity)
        }
        pub fn router_with_identity(store: Store, token: String, host: String, identity: crate::oidc::Identity) -> Router {
            let scim = crate::scim::Service::new(store.clone());
            router_with_services(store, token, host, identity, scim)
        }
        pub fn router_with_services(store: Store, token: String, host: String, identity: crate::oidc::Identity, scim: crate::scim::Service) -> Router {
            let tunnel = crate::tunnel::Service::unavailable(store.clone());
            router_with_tunnel(store, token, host, identity, scim, tunnel)
        }
        pub fn router_with_tunnel(store: Store, token: String, host: String, identity: crate::oidc::Identity, scim: crate::scim::Service, tunnel: crate::tunnel::Service) -> Router {
            router_with_runtime(store, token, host, identity, scim, tunnel, None)
        }
        pub(crate) fn router_with_runtime(store: Store, token: String, host: String, identity: crate::oidc::Identity, scim: crate::scim::Service, tunnel: crate::tunnel::Service, activation:Option<tokio::sync::watch::Sender<u64>>) -> Router {
            let diagnostics = identity.diagnostics();
            let state = ApiState { store, identity, scim, tunnel, tunneled: false, token, host, diagnostics, activation };
            let router = Router::new();
            $(let router = router.route($path, axum::routing::$method($handler));)+
            router
                .fallback(|| async { ApiError(StatusCode::NOT_FOUND, "API route not found".into()) })
                .method_not_allowed_fallback(|| async { ApiError(StatusCode::METHOD_NOT_ALLOWED, "method not allowed".into()) })
                .route("/-/ready", get(|| async { StatusCode::NO_CONTENT }))
                .route("/-/activate", axum::routing::post(activate))
                .layer(DefaultBodyLimit::max(25 << 20))
                .route("/api/v1/", get(catalog))
                .layer(middleware::from_fn(validate_body))
                .layer(middleware::from_fn_with_state(state.clone(), authenticate))
                .with_state(state.clone())
                .merge(keys::router(state.clone()))
                .merge(lifecycle::router(state.clone()))
                .merge(playground::router(state.clone()))
                .merge(oidc::router(state.clone()))
                .merge(saml::router(state.clone()))
                .layer(middleware::from_fn_with_state(state, account::local_boundary))
        }

        fn routes() -> Vec<Value> {
            let mut routes = Vec::new();
            $(let fields: Vec<&str> = $fields;
              let mut route = json!({"method": stringify!($method).to_ascii_uppercase(), "path": $path});
              if !fields.is_empty() { route["fields"] = json!(fields); }
              routes.push(route);)+
            routes
        }
        fn mutates_state(method: &Method, path: &str) -> bool {
            $(if method.as_str().eq_ignore_ascii_case(stringify!($method)) && path == $path { return $mutates; })+
            false
        }
    };
}

async fn activate(State(state): State<ApiState>) -> StatusCode {
    let Some(activation) = state.activation else {
        return StatusCode::NOT_FOUND;
    };
    activation.send_modify(|value| *value = value.wrapping_add(1));
    StatusCode::NO_CONTENT
}

fn environment_fields() -> Vec<&'static str> {
    [vec!["name", "slug"], SettingsPatch::FIELDS.to_vec()].concat()
}

const USER_FIELDS: &[&str] = &[
    "given_name",
    "family_name",
    "email",
    "username",
    "active",
    "employee_number",
    "cost_center",
    "organization",
    "division",
    "department",
    "manager_id",
    "attributes",
];
const GROUP_FIELDS: &[&str] = &["display_name", "member_ids"];

api_routes! {
    get "/api/v1", vec![] => catalog, false;
    get "/api/v1/status", vec![] => status, false;
    get "/api/v1/account", vec![] => account, false;
    post "/api/v1/account/start", vec![] => account_start, false;
    post "/api/v1/account/retry", vec![] => account_retry, false;
    post "/api/v1/account/logout", vec![] => account_logout, false;
    get "/api/v1/tunnel", vec![] => tunnel, false;
    post "/api/v1/tunnel/retry", vec![] => tunnel_retry, false;
    get "/api/v1/config", vec![] => configuration, false;
    patch "/api/v1/config", vec!["idp_base_url", "trust_forwarded_headers", "debug", "record_traffic", "record_secrets"] => update_configuration, true;
    get "/api/v1/traffic", vec![] => traffic_snapshot, false;
    patch "/api/v1/traffic/settings", vec!["record", "record_secrets"] => traffic_settings, false;
    delete "/api/v1/traffic", vec![] => traffic_clear, false;
    get "/api/v1/environments", vec![] => environments, false;
    post "/api/v1/environments", environment_fields() => create_environment, true;
    get "/api/v1/environments/{environment_id}", vec![] => environment, false;
    patch "/api/v1/environments/{environment_id}", environment_fields() => update_environment, true;
    delete "/api/v1/environments/{environment_id}", vec![] => delete_environment, true;
    get "/api/v1/environments/{environment_id}/users", vec![] => users, false;
    post "/api/v1/environments/{environment_id}/users", USER_FIELDS.to_vec() => create_user, true;
    get "/api/v1/environments/{environment_id}/users/{user_id}", vec![] => user, false;
    patch "/api/v1/environments/{environment_id}/users/{user_id}", USER_FIELDS.to_vec() => update_user, true;
    delete "/api/v1/environments/{environment_id}/users/{user_id}", vec![] => delete_user, true;
    post "/api/v1/environments/{environment_id}/users/{user_id}/restore", vec![] => restore_user, true;
    get "/api/v1/environments/{environment_id}/users/{user_id}/operations", vec![] => user_operations, false;
    post "/api/v1/environments/{environment_id}/users/bulk-delete", vec!["ids"] => delete_users, true;
    get "/api/v1/environments/{environment_id}/groups", vec![] => groups, false;
    post "/api/v1/environments/{environment_id}/groups", GROUP_FIELDS.to_vec() => create_group, true;
    get "/api/v1/environments/{environment_id}/groups/{group_id}", vec![] => group, false;
    patch "/api/v1/environments/{environment_id}/groups/{group_id}", GROUP_FIELDS.to_vec() => update_group, true;
    delete "/api/v1/environments/{environment_id}/groups/{group_id}", vec![] => delete_group, true;
    post "/api/v1/environments/{environment_id}/groups/{group_id}/restore", vec![] => restore_group, true;
    get "/api/v1/environments/{environment_id}/groups/{group_id}/operations", vec![] => group_operations, false;
    post "/api/v1/environments/{environment_id}/groups/bulk-delete", vec!["ids"] => delete_groups, true;
    post "/api/v1/environments/{environment_id}/tools/seed-sample", vec![] => seed_sample, true;
    post "/api/v1/environments/{environment_id}/tools/create-users", vec!["count", "email_domain"] => create_users, true;
    post "/api/v1/environments/{environment_id}/tools/activate-all", vec![] => activate_all, true;
    post "/api/v1/environments/{environment_id}/tools/deactivate-all", vec![] => deactivate_all, true;
    post "/api/v1/environments/{environment_id}/tools/delete-all", vec![] => delete_all, true;
    post "/api/v1/environments/{environment_id}/tools/clear-local", vec![] => clear_local, true;
    get "/api/v1/environments/{environment_id}/backup", vec![] => backup, false;
    post "/api/v1/environments/{environment_id}/import/preview", vec![] => import_preview, true;
    get "/api/v1/environments/{environment_id}/import/preview", vec![] => import_preview_get, false;
    post "/api/v1/environments/{environment_id}/import/apply", vec![] => import_apply, true;
    post "/api/v1/environments/{environment_id}/scim/discover", vec![] => scim_discover, true;
    post "/api/v1/environments/{environment_id}/scim/test", vec![] => scim_test, true;
    get "/api/v1/environments/{environment_id}/sync/plan", vec![] => sync_plan, false;
    get "/api/v1/environments/{environment_id}/sync/status", vec![] => sync_status, false;
    post "/api/v1/environments/{environment_id}/sync/start", vec![] => sync_start, false;
    post "/api/v1/environments/{environment_id}/sync/reconcile", vec![] => reconcile, false;
    post "/api/v1/environments/{environment_id}/sync/cancel", vec![] => sync_cancel, false;
    post "/api/v1/environments/{environment_id}/sync/reset", vec![] => sync_reset, true;
    get "/api/v1/environments/{environment_id}/sync/trace", vec![] => sync_trace, false;
    post "/api/v1/environments/{environment_id}/users/{user_id}/push", vec![] => push_user, false;
    post "/api/v1/environments/{environment_id}/groups/{group_id}/push", vec![] => push_group, false;
    post "/api/v1/environments/{environment_id}/saml/sign-in", vec!["user_id", "login_identifier", "relay_state", "saml_request", "sig_alg", "signature", "redirect_query", "authn_strength"] => saml_sign_in, false;
    post "/api/v1/environments/{environment_id}/saml/logout", vec!["session_id", "binding"] => saml_logout, false;
    get "/api/v1/environments/{environment_id}/saml/logouts", vec![] => saml_logouts, false;
    post "/api/v1/environments/{environment_id}/oidc/authorize", vec!["user_id", "login_identifier", "response_type", "client_id", "redirect_uri", "state", "scope", "nonce", "code_challenge", "code_challenge_method", "acr_values", "authn_strength"] => authorize, false;
    post "/api/v1/environments/{environment_id}/oidc/playground", vec!["user_id", "login_identifier", "faults", "refresh"] => playground, false;
    get "/api/v1/environments/{environment_id}/oidc/tokens", vec![] => oidc_tokens, false;
    delete "/api/v1/environments/{environment_id}/oidc/tokens", vec![] => revoke_oidc_tokens, false;
    get "/api/v1/environments/{environment_id}/sessions", vec![] => sessions, false;
    delete "/api/v1/environments/{environment_id}/sessions", vec![] => end_sessions, false;
    get "/api/v1/environments/{environment_id}/inspections/{protocol}", vec![] => inspections, false;
    get "/api/v1/environments/{environment_id}/flows", vec![] => flows, false;
    get "/api/v1/environments/{environment_id}/faults", vec![] => fault_get, false;
    put "/api/v1/environments/{environment_id}/faults", vec!["id_token_ttl", "assertion_ttl", "clock_skew", "break_signature", "drop_claims", "token_error", "saml_status", "tamper"] => fault_put, false;
    delete "/api/v1/environments/{environment_id}/faults", vec![] => fault_delete, false;
    get "/api/v1/environments/{environment_id}/scenarios", vec![] => scenarios_get, false;
    post "/api/v1/environments/{environment_id}/scenarios/arm", vec!["preset_id", "count"] => scenarios_arm, false;
    post "/api/v1/environments/{environment_id}/scenarios/disarm", vec![] => scenarios_disarm, false;
    get "/api/v1/environments/{environment_id}/connection", vec![] => connection, false;
    get "/api/v1/environments/{environment_id}/lifecycle", vec![] => lifecycle_list, false;
    get "/api/v1/environments/{environment_id}/lifecycle/{run_id}", vec![] => lifecycle_get, false;
    post "/api/v1/environments/{environment_id}/lifecycle/joiner", vec!["given_name", "family_name", "email", "username", "group_ids"] => lifecycle_joiner, true;
    post "/api/v1/environments/{environment_id}/lifecycle/mover", vec!["user_id", "add_group_ids", "remove_group_ids"] => lifecycle_mover, true;
    post "/api/v1/environments/{environment_id}/lifecycle/leaver", vec!["user_id"] => lifecycle_leaver, true;
    get "/api/v1/environments/{environment_id}/signing-keys", vec![] => signing_keys, false;
    post "/api/v1/environments/{environment_id}/signing-keys/rotate", vec!["grace_period", "certificate_validity"] => rotate_key, true;
    post "/api/v1/environments/{environment_id}/restore", vec!["version", "exported_at", "state", "user_operations", "group_operations", "user_sync", "group_sync"] => restore_backup, true;
}

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}

impl From<Error> for ApiError {
    fn from(error: Error) -> Self {
        if let Error::Json(error) = &error {
            return Self(StatusCode::BAD_REQUEST, format!("invalid JSON: {error}"));
        }
        if matches!(&error,Error::Conflict(message) if message=="a sync is running; wait for it to finish or cancel it")
        {
            return Self(
                StatusCode::CONFLICT,
                "sync is running; wait for it to finish before changing state".into(),
            );
        }
        let status = match &error {
            Error::Validation(_) | Error::Json(_) => StatusCode::BAD_REQUEST,
            Error::Conflict(_) => StatusCode::CONFLICT,
            Error::NotFound(_) => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            eprintln!("scimtest API: {error}");
            return Self(status, "Could not complete the database operation".into());
        }
        Self(status, error.to_string())
    }
}

fn decode<T: DeserializeOwned>(body: Result<Json<Value>, JsonRejection>) -> Result<T, ApiError> {
    let Json(value) = body.map_err(|error| ApiError(error.status(), error.body_text()))?;
    if !value.is_object() || has_null(&value) {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "Body must be an object without null fields".into(),
        ));
    }
    serde_json::from_value(value)
        .map_err(Error::from)
        .map_err(ApiError::from)
}

fn decode_optional<T: DeserializeOwned + Default>(
    headers: &axum::http::HeaderMap,
    bytes: &[u8],
) -> Result<T, ApiError> {
    if bytes.is_empty() {
        return Ok(T::default());
    }
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| {
            value.split(';').next().unwrap_or_default().trim() != "application/json"
        })
    {
        return Err(ApiError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/json".into(),
        ));
    }
    let value = serde_json::from_slice(bytes).map_err(Error::from)?;
    decode(Ok(Json(value)))
}

async fn run<T: Send + 'static>(
    state: ApiState,
    action: impl FnOnce(Store) -> Result<T, Error> + Send + 'static,
) -> Result<Json<T>, ApiError> {
    let result = tokio::task::spawn_blocking(move || action(state.store))
        .await
        .map_err(|error| ApiError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))??;
    Ok(Json(result))
}

async fn catalog() -> Json<Value> {
    Json(json!({"version": "v1", "routes": routes()}))
}

async fn status(State(state): State<ApiState>) -> Result<Json<Value>, ApiError> {
    let config = configuration(State(state.clone())).await?.0;
    let snapshot = state.tunnel.snapshot()?;
    let locked = !state.tunnel.unlocked()?;
    let mut tunnel = json!({"supported":snapshot.supported,"starting":snapshot.starting,"connected":snapshot.connected,"error":snapshot.error});
    if snapshot.connected {
        tunnel["public_url"] = json!(snapshot.public_url);
    }
    run(state, move |store| Ok(json!({"ready": true, "locked": locked, "environments": store.snapshot()?.len(), "debug": config.debug, "traffic": {"record": config.record_traffic, "record_secrets": config.record_secrets}, "tunnel": tunnel}))).await
}

async fn configuration(State(state): State<ApiState>) -> Result<Json<GlobalConfig>, ApiError> {
    let diagnostics = state.diagnostics.settings()?;
    run(state, move |store| {
        let mut config = store.global_config()?;
        config.debug = diagnostics.debug;
        config.record_traffic = diagnostics.record;
        config.record_secrets = diagnostics.record_secrets;
        Ok(config)
    })
    .await
}

async fn update_configuration(
    State(state): State<ApiState>,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<Json<GlobalConfig>, ApiError> {
    let patch: GlobalConfigPatch = decode(body)?;
    let saved_patch = GlobalConfigPatch {
        idp_base_url: patch.idp_base_url,
        trust_forwarded_headers: patch.trust_forwarded_headers,
        ..Default::default()
    };
    if saved_patch.idp_base_url.is_some() || saved_patch.trust_forwarded_headers.is_some() {
        let Json(()) = run(state.clone(), move |store| {
            store.update_global_config(&saved_patch)
        })
        .await?;
    }
    state
        .diagnostics
        .update(patch.debug, patch.record_traffic, patch.record_secrets)?;
    configuration(State(state)).await
}

async fn environments(State(state): State<ApiState>) -> Result<Json<Vec<Environment>>, ApiError> {
    run(state, |store| {
        Ok(store
            .snapshot()?
            .into_iter()
            .map(|directory| directory.environment)
            .collect())
    })
    .await
}

async fn environment(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Environment>, ApiError> {
    run(state, move |store| Ok(store.directory(&id)?.environment)).await
}

async fn create_environment(
    State(state): State<ApiState>,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let input = decode(body)?;
    Ok((
        StatusCode::CREATED,
        run(state, move |store| store.create_environment(input)).await?,
    ))
}

async fn update_environment(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<Json<Environment>, ApiError> {
    let patch = decode(body)?;
    run(state, move |store| store.update_environment(&id, patch)).await
}

async fn delete_environment(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    run(state, move |store| {
        store.delete_environment(&id)?;
        Ok(json!({"message": "environment deleted"}))
    })
    .await
}

async fn users(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<User>>, ApiError> {
    run(state, move |store| {
        Ok(store.directory(&id)?.projected_users())
    })
    .await
}

async fn user(
    State(state): State<ApiState>,
    Path((environment, id)): Path<(String, String)>,
) -> Result<Json<User>, ApiError> {
    run(state, move |store| {
        store
            .directory(&environment)?
            .projected_users()
            .into_iter()
            .find(|user| user.id == id)
            .ok_or(Error::NotFound("user"))
    })
    .await
}

async fn create_user(
    State(state): State<ApiState>,
    Path(environment): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let input = decode(body)?;
    Ok((
        StatusCode::CREATED,
        run(state, move |store| store.create_user(&environment, input)).await?,
    ))
}

async fn update_user(
    State(state): State<ApiState>,
    Path((environment, id)): Path<(String, String)>,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<Json<User>, ApiError> {
    let patch = decode(body)?;
    run(state, move |store| {
        store.update_user(&environment, &id, patch)
    })
    .await
}

async fn delete_user(
    State(state): State<ApiState>,
    Path((environment, id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    run(state, move |store| {
        let tracked = store.directory(&environment)?.tracks_scim();
        store.delete_user(&environment, &id)?;
        Ok(json!({"message": if tracked { "user marked for deletion" } else { "user deleted" }}))
    })
    .await
}

async fn groups(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<Value>>, ApiError> {
    run(state, move |store| {
        let directory = store.directory(&id)?;
        let null_members = !directory.environment.settings.scim_enabled;
        directory
            .projected_groups()
            .into_iter()
            .map(|group| group_value(group, null_members))
            .collect()
    })
    .await
}

async fn group(
    State(state): State<ApiState>,
    Path((environment, id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    run(state, move |store| {
        let directory = store.directory(&environment)?;
        let null_members = !directory.environment.settings.scim_enabled;
        let group = directory
            .projected_groups()
            .into_iter()
            .find(|group| group.id == id)
            .ok_or(Error::NotFound("group"))?;
        group_value(group, null_members)
    })
    .await
}

async fn create_group(
    State(state): State<ApiState>,
    Path(environment): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let patch: GroupPatch = decode(body)?;
    let null_members = patch.member_ids.is_none();
    let input = GroupInput {
        display_name: patch.display_name.unwrap_or_default(),
        member_ids: patch.member_ids.unwrap_or_default(),
    };
    Ok((
        StatusCode::CREATED,
        run(state, move |store| {
            group_value(store.create_group(&environment, input)?, null_members)
        })
        .await?,
    ))
}

async fn update_group(
    State(state): State<ApiState>,
    Path((environment, id)): Path<(String, String)>,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let patch: GroupPatch = decode(body)?;
    let null_members = patch.member_ids.is_none();
    run(state, move |store| {
        group_value(store.update_group(&environment, &id, patch)?, null_members)
    })
    .await
}
fn group_value(group: Group, null_members: bool) -> Result<Value, Error> {
    let empty = group.fields.member_ids.is_empty();
    let mut value = serde_json::to_value(group)?;
    if empty && null_members {
        value["member_ids"] = Value::Null;
    }
    Ok(value)
}

async fn delete_group(
    State(state): State<ApiState>,
    Path((environment, id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    run(state, move |store| {
        let tracked = store.directory(&environment)?.tracks_scim();
        store.delete_group(&environment, &id)?;
        Ok(json!({"message": if tracked { "group marked for deletion" } else { "group deleted" }}))
    })
    .await
}

async fn seed_sample(
    State(state): State<ApiState>,
    Path(environment): Path<String>,
) -> Result<Json<Value>, ApiError> {
    run(state, move |store| {
        let result = store.seed_sample(&environment)?;
        Ok(json!({"users_changed": result.users_added, "groups_changed": result.groups_added}))
    })
    .await
}

fn has_null(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(fields) => fields.values().any(has_null),
        Value::Array(items) => items.iter().any(has_null),
        _ => false,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    ids: Vec<String>,
}

async fn delete_users(
    State(state): State<ApiState>,
    Path(environment): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let selected: Selection = decode(body)?;
    run(state, move |store| {
        Ok(json!({"deleted": store.delete_users(&environment, &selected.ids)?}))
    })
    .await
}

async fn delete_groups(
    State(state): State<ApiState>,
    Path(environment): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let selected: Selection = decode(body)?;
    run(state, move |store| {
        Ok(json!({"deleted": store.delete_groups(&environment, &selected.ids)?}))
    })
    .await
}

async fn restore_user(
    State(state): State<ApiState>,
    Path((environment, id)): Path<(String, String)>,
) -> Result<Json<User>, ApiError> {
    run(state, move |store| store.restore_user(&environment, &id)).await
}

async fn restore_group(
    State(state): State<ApiState>,
    Path((environment, id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    run(state, move |store| {
        group_value(store.restore_group(&environment, &id)?, true)
    })
    .await
}

async fn user_operations(
    State(state): State<ApiState>,
    Path((environment, id)): Path<(String, String)>,
) -> Result<Json<Vec<OperationLog>>, ApiError> {
    run(state, move |store| {
        let mut directory = store.directory(&environment)?;
        if !directory.users.iter().any(|user| user.id == id) {
            return Err(Error::NotFound("user"));
        }
        Ok(directory.user_operations.remove(&id).unwrap_or_default())
    })
    .await
}

async fn group_operations(
    State(state): State<ApiState>,
    Path((environment, id)): Path<(String, String)>,
) -> Result<Json<Vec<OperationLog>>, ApiError> {
    run(state, move |store| {
        let mut directory = store.directory(&environment)?;
        if !directory.groups.iter().any(|group| group.id == id) {
            return Err(Error::NotFound("group"));
        }
        Ok(directory.group_operations.remove(&id).unwrap_or_default())
    })
    .await
}

async fn backup(
    State(state): State<ApiState>,
    Path(environment): Path<String>,
) -> Result<Json<StateBackup>, ApiError> {
    run(state, move |store| store.backup(&environment)).await
}

async fn restore_backup(
    State(state): State<ApiState>,
    Path(environment): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(value) = body.map_err(|error| ApiError(error.status(), error.body_text()))?;
    let backup = serde_json::from_value(value).map_err(Error::from)?;
    run(state, move |store| Ok(json!({"message": "backup restored", "safety_backup": store.restore_backup(&environment, backup)?}))).await
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CreateUsers {
    count: usize,
    email_domain: String,
}

impl Default for CreateUsers {
    fn default() -> Self {
        Self {
            count: 10,
            email_domain: "greendale.edu".into(),
        }
    }
}

async fn create_users(
    State(state): State<ApiState>,
    Path(environment): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<Json<crate::tools::ToolResult>, ApiError> {
    let input: CreateUsers = decode(body)?;
    run(state, move |store| {
        store.create_users(&environment, input.count, &input.email_domain)
    })
    .await
}

async fn activate_all(
    State(state): State<ApiState>,
    Path(environment): Path<String>,
) -> Result<Json<crate::tools::ToolResult>, ApiError> {
    run(state, move |store| store.set_all_active(&environment, true)).await
}

async fn deactivate_all(
    State(state): State<ApiState>,
    Path(environment): Path<String>,
) -> Result<Json<crate::tools::ToolResult>, ApiError> {
    run(state, move |store| {
        store.set_all_active(&environment, false)
    })
    .await
}

async fn delete_all(
    State(state): State<ApiState>,
    Path(environment): Path<String>,
) -> Result<Json<crate::tools::ToolResult>, ApiError> {
    run(state, move |store| store.delete_all_users(&environment)).await
}

async fn clear_local(
    State(state): State<ApiState>,
    Path(environment): Path<String>,
) -> Result<Json<crate::tools::ToolResult>, ApiError> {
    run(state, move |store| store.clear_directory(&environment)).await
}
