use super::*;
use crate::scim::{Mode, Service};
use axum::extract::Query;

async fn operation<T>(
    state: ApiState,
    action: impl FnOnce(Service) -> Result<T, Error> + Send + 'static,
) -> Result<Json<T>, ApiError>
where
    T: serde::Serialize + Send + 'static,
{
    tokio::task::spawn_blocking(move || action(state.scim))
        .await
        .map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SCIM operation failed".into(),
            )
        })?
        .map(Json)
        .map_err(Into::into)
}
pub(super) async fn plan(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    run(state, move |store| {
        let directory = store.directory(&id)?;
        if !directory.environment.settings.scim_enabled {
            return Err(Error::Validation(
                "SCIM is not enabled for the active environment".into(),
            ));
        }
        let entries = crate::scim::plan(&directory);
        let mut lines = entries
            .iter()
            .take(12)
            .map(|entry| {
                format!(
                    "{} {} {}",
                    entry.operation, entry.resource_type, entry.label
                )
            })
            .collect::<Vec<_>>();
        if entries.len() > 12 {
            lines.push(format!("… and {} more", entries.len() - 12));
        }
        let summary = if entries.is_empty() {
            "Nothing is pending; sync will verify credentials and stop".into()
        } else {
            lines.join("\n")
        };
        Ok(json!({"entries":entries,"summary":summary}))
    })
    .await
}
pub(super) async fn status(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(query): Query<crate::oidc::Parameters>,
) -> Result<Json<Option<crate::scim::Job>>, ApiError> {
    let after = query
        .get("after")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| {
            ApiError(
                StatusCode::BAD_REQUEST,
                "after must be a non-negative integer".into(),
            )
        })?
        .unwrap_or_default();
    operation(state, move |service| service.status(&id, after)).await
}
async fn start(state: ApiState, id: String, mode: Mode) -> Result<Response, ApiError> {
    let Json(job) = operation(state, move |service| service.start(&id, mode)).await?;
    Ok((StatusCode::ACCEPTED, Json(job)).into_response())
}
pub(super) async fn sync(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    start(state, id, Mode::Sync).await
}
pub(super) async fn reconcile(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    start(state, id, Mode::Reconcile).await
}
pub(super) async fn push_user(
    State(state): State<ApiState>,
    Path((id, user)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    start(
        state,
        id,
        Mode::Push {
            resource_type: "user".into(),
            resource_id: user,
        },
    )
    .await
}
pub(super) async fn push_group(
    State(state): State<ApiState>,
    Path((id, group)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    start(
        state,
        id,
        Mode::Push {
            resource_type: "group".into(),
            resource_id: group,
        },
    )
    .await
}
pub(super) async fn cancel(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    operation(state, move |service| {
        service.cancel(&id)?;
        Ok(json!({"message":"stopping sync"}))
    })
    .await
}
pub(super) async fn reset(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    run(state, move |store| {
        let (users, groups) = store.reset_scim(&id)?;
        Ok(json!({"users":users,"groups":groups}))
    })
    .await
}
pub(super) async fn trace(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<crate::scim::Trace>>, ApiError> {
    operation(state, move |service| service.traces(&id)).await
}
pub(super) async fn discover(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (patch, filter) = state.scim.discover(id, true).await?;
    Ok(Json(
        json!({"patch_supported":patch,"filter_supported":filter}),
    ))
}
pub(super) async fn test(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (patch, filter) = state.scim.discover(id, false).await?;
    Ok(Json(
        json!({"connected":true,"patch_supported":patch,"filter_supported":filter}),
    ))
}

pub(super) async fn import_preview(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let mut value =
        serde_json::to_value(state.scim.preview_import(id).await?).map_err(Error::from)?;
    value.as_object_mut().unwrap().remove("created_at");
    Ok(Json(value))
}
pub(super) async fn import_preview_get(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<crate::scim::PreviewView>, ApiError> {
    operation(state, move |service| service.import_preview(&id)).await
}
pub(super) async fn import_apply(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    operation(state, move |service| {
        Ok(json!({"message":service.apply_import(&id)?}))
    })
    .await
}
