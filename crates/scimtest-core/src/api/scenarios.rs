use super::*;
use axum::{body::Bytes, http::HeaderMap};
pub(super) async fn get(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    oidc::protocol(state, move |identity, _| {
        let presets = identity
            .resilience_presets(&id)?
            .iter()
            .map(|preset| preset.api_value())
            .collect::<Vec<_>>();
        let run = identity.resilience_run(&id)?.map(|run| run.api_value());
        Ok(Json(json!({"presets":presets,"run":run})))
    })
    .await
    .map_err(error)
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Input {
    preset_id: String,
    count: Option<Value>,
}
pub(super) async fn arm(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    let input: Input = decode_optional(&headers, &bytes)?;
    let count = parse_count(input.count)?;
    let run = oidc::protocol(state, move |identity, _| {
        let preset = identity
            .resilience_presets(&id)?
            .into_iter()
            .find(|preset| preset.id == input.preset_id)
            .ok_or_else(|| {
                crate::oidc::ProtocolError::new(
                    "invalid_request",
                    "scenario is not available for this environment",
                )
            })?;
        let count = if !preset.allow_count {
            0
        } else {
            i32::try_from(count).map_err(|_| crate::oidc::ProtocolError {
                status: 409,
                ..crate::oidc::ProtocolError::new(
                    "invalid_request",
                    "failure count must be between 1 and 20",
                )
            })?
        };
        let run = identity
            .arm_resilience(&id, preset.id, count)
            .map_err(|mut error| {
                error.status = 409;
                error
            })?;
        identity.disarm_faults(&id)?;
        Ok(Json(run.api_value()))
    })
    .await
    .map_err(error)?;
    Ok((StatusCode::CREATED, run))
}
pub(super) async fn disarm(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    oidc::protocol(state, move |identity, _| {
        if !identity.disarm_resilience(&id)? {
            return Err(crate::oidc::ProtocolError {
                status: 409,
                ..crate::oidc::ProtocolError::new(
                    "invalid_request",
                    "no fault injection scenario is active",
                )
            });
        }
        Ok(Json(
            identity
                .resilience_run(&id)?
                .map(|run| run.api_value())
                .unwrap_or(Value::Null),
        ))
    })
    .await
    .map_err(error)
}
fn parse_count(value: Option<Value>) -> Result<i64, ApiError> {
    let invalid = || ApiError(StatusCode::BAD_REQUEST, "count must be an integer".into());
    match value {
        None => Ok(0),
        Some(Value::String(value)) => value.parse().map_err(|_| invalid()),
        Some(Value::Number(value)) => value
            .as_i64()
            .or_else(|| {
                value
                    .as_f64()
                    .filter(|value| {
                        value.fract() == 0.0
                            && *value >= i64::MIN as f64
                            && *value < i64::MAX as f64
                    })
                    .map(|value| value as i64)
            })
            .ok_or_else(invalid),
        _ => Err(invalid()),
    }
}
fn error(error: crate::oidc::ProtocolError) -> ApiError {
    ApiError(
        StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        error.description,
    )
}
