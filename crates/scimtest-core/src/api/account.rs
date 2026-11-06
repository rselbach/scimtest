use super::*;
use axum::{http::Uri, response::Html};
use std::net::IpAddr;

pub(super) async fn account(State(state): State<ApiState>) -> Result<Json<Value>, ApiError> {
    Ok(Json(state.tunnel.account()?))
}
pub(super) async fn account_start(State(state): State<ApiState>) -> Result<Json<Value>, ApiError> {
    require_account(&state)?;
    account(State(state)).await
}
pub(super) async fn account_retry(State(state): State<ApiState>) -> Result<Json<Value>, ApiError> {
    state.tunnel.retry()?;
    account(State(state)).await
}
pub(super) async fn account_logout(State(state): State<ApiState>) -> Result<Json<Value>, ApiError> {
    require_account(&state)?;
    state.tunnel.logout().await?;
    account(State(state)).await
}
fn require_account(state: &ApiState) -> Result<(), ApiError> {
    if state.tunnel.required() {
        return Ok(());
    }
    Err(ApiError(
        StatusCode::NOT_FOUND,
        "account sign-in is not enabled".into(),
    ))
}
pub(super) async fn tunnel(
    State(state): State<ApiState>,
) -> Result<Json<crate::tunnel::Snapshot>, ApiError> {
    Ok(Json(state.tunnel.snapshot()?))
}
pub(super) async fn tunnel_retry(
    State(state): State<ApiState>,
) -> Result<Json<crate::tunnel::Snapshot>, ApiError> {
    state.tunnel.retry()?;
    tunnel(State(state)).await
}

pub(super) async fn local_boundary(
    State(state): State<ApiState>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = match local_access(&state, &request) {
        Ok(true)
            if (request.uri().path().starts_with("/api/v1")
                || request.uri().path() == "/-/activate")
                && super::request::cross_origin(&request) =>
        {
            ApiError(
                StatusCode::FORBIDDEN,
                "cross-origin API request rejected".into(),
            )
            .into_response()
        }
        Ok(true) => next.run(request).await,
        Ok(false) if request.method() == Method::GET && request.uri().path() == "/" => {
            Html(super::oidc::page(
                "Sign in to scimtest",
                "<p>Continue with GitHub in the desktop app to unlock scimtest.</p>",
            ))
            .into_response()
        }
        Ok(false) => ApiError(
            StatusCode::UNAUTHORIZED,
            "GitHub account sign-in is required".into(),
        )
        .into_response(),
        Err(error) => error.into_response(),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
fn local_access(state: &ApiState, request: &Request) -> Result<bool, ApiError> {
    if request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        != Some(&state.host)
    {
        if ["/oidc/", "/saml/", "/.well-known/"]
            .iter()
            .any(|prefix| request.uri().path().starts_with(prefix))
        {
            return Err(ApiError(StatusCode::FORBIDDEN, "Invalid local host".into()));
        }
        return Err(ApiError(
            StatusCode::MISDIRECTED_REQUEST,
            "unrecognized admin host".into(),
        ));
    }
    if state.tunnel.unlocked()? {
        return Ok(true);
    }
    Ok(matches!(
        request.uri().path(),
        "/api/v1"
            | "/api/v1/"
            | "/api/v1/status"
            | "/api/v1/account"
            | "/api/v1/account/start"
            | "/api/v1/account/retry"
            | "/api/v1/tunnel"
            | "/api/v1/tunnel/retry"
    ) || request.method() == Method::GET && request.uri().path() == "/-/ready"
        || request.method() == Method::POST && request.uri().path() == "/-/activate")
}

#[derive(Clone)]
pub(super) struct PublicUri(pub Uri);

pub(super) async fn public_boundary(
    State(state): State<ApiState>,
    mut request: Request,
    next: Next,
) -> Response {
    if request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        != Some(&state.host)
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    let endpoint = match state.tunnel.public_endpoint() {
        Ok(Some(endpoint)) => endpoint,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(error) => return ApiError::from(error).into_response(),
    };
    let Some(path) = request
        .uri()
        .path()
        .strip_prefix(&endpoint.prefix)
        .filter(|path| path.starts_with('/'))
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let segments = path.split('/').collect::<Vec<_>>();
    if matches!(
        (segments.get(1), segments.get(3)),
        (Some(&"oidc"), Some(&"authorize")) | (Some(&"saml"), Some(&"sso"))
    ) {
        let visitor = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .unwrap_or_default()
            .trim();
        let allowed = endpoint
            .client_ip
            .trim()
            .parse::<IpAddr>()
            .ok()
            .map(|ip| ip.to_canonical());
        let visitor = visitor.parse::<IpAddr>().ok().map(|ip| ip.to_canonical());
        if allowed.is_none() || visitor != allowed {
            return (
                StatusCode::FORBIDDEN,
                "Sign-in is limited to the network where scimtest is running",
            )
                .into_response();
        }
    }
    let mut target = path.to_owned();
    if let Some(query) = request.uri().query() {
        target.push('?');
        target.push_str(query);
    }
    let Ok(uri) = target.parse::<Uri>() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let original = PublicUri(request.uri().clone());
    request.extensions_mut().insert(original);
    *request.uri_mut() = uri;
    next.run(request).await
}
