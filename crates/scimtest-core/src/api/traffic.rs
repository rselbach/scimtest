use super::*;
use crate::diagnostics::{Diagnostics, Exchange, Settings, Snapshot, transcript};
use axum::{
    body::{Body, Bytes, HttpBody},
    http::{HeaderMap, Version},
};

pub(super) async fn snapshot(State(state): State<ApiState>) -> Result<Json<Snapshot>, ApiError> {
    Ok(Json(state.diagnostics.snapshot()?))
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Input {
    record: Option<bool>,
    record_secrets: Option<bool>,
}
pub(super) async fn settings(
    State(state): State<ApiState>,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<Json<Snapshot>, ApiError> {
    let input: Input = decode(body)?;
    state
        .diagnostics
        .update(None, input.record, input.record_secrets)?;
    Ok(Json(state.diagnostics.snapshot()?))
}
pub(super) async fn clear(State(state): State<ApiState>) -> Result<StatusCode, ApiError> {
    state.diagnostics.clear()?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) struct Captured {
    method: Method,
    uri: String,
    version: Version,
    headers: HeaderMap,
    body: Bytes,
    settings: Settings,
}
pub(super) async fn capture_request(
    state: &ApiState,
    request: Request,
) -> Result<(Request, Option<Captured>), ApiError> {
    let settings = state.diagnostics.settings().map_err(ApiError::from)?;
    if !settings.debug && !settings.record {
        return Ok((request, None));
    }
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 20).await.map_err(|_| {
        ApiError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body too large".into(),
        )
    })?;
    let captured = Captured {
        method: parts.method.clone(),
        uri: parts
            .extensions
            .get::<super::account::PublicUri>()
            .map(|uri| &uri.0)
            .unwrap_or(&parts.uri)
            .to_string(),
        version: parts.version,
        headers: parts.headers.clone(),
        body: bytes.clone(),
        settings,
    };
    Ok((
        Request::from_parts(parts, Body::from(bytes)),
        Some(captured),
    ))
}
pub(super) async fn capture_response(
    diagnostics: Diagnostics,
    captured: Option<Captured>,
    response: Response,
) -> Response {
    let Some(captured) = captured else {
        return response;
    };
    let (parts, body) = response.into_parts();
    let limit = 10 << 20;
    let (body, bytes) = if body
        .size_hint()
        .upper()
        .is_some_and(|length| length <= limit as u64)
    {
        match axum::body::to_bytes(body, limit).await {
            Ok(bytes) => (Body::from(bytes.clone()), bytes),
            Err(error) => {
                eprintln!("Capture identity response: {error}");
                (
                    Body::empty(),
                    Bytes::from_static(b"[response body unavailable]"),
                )
            }
        }
    } else {
        (
            body,
            Bytes::from_static(b"[response body omitted: larger than 10 MiB or streaming]"),
        )
    };
    let text = transcript(
        Exchange {
            title: "RP interaction",
            method: captured.method.as_str(),
            uri: &captured.uri,
            version: captured.version,
            request_headers: &captured.headers,
            request_body: &captured.body,
            status: Some(parts.status),
            response_headers: &parts.headers,
            response_body: &bytes,
        },
        captured.settings,
    );
    if let Err(error) = diagnostics.record(text, captured.settings) {
        eprintln!("Record identity traffic: {error}");
    }
    Response::from_parts(parts, body)
}
