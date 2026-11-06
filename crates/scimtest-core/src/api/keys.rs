use super::*;
use crate::signing::{CertificateValidity, SigningKeyView, parse_grace};
use axum::{body::Bytes, http::HeaderMap};

fn require_idp(store: &Store, environment: &str) -> Result<Environment, Error> {
    let environment = store.directory(environment)?.environment;
    if !environment.settings.supports_oidc() && !environment.settings.supports_saml() {
        return Err(Error::Validation("OIDC or SAML is not enabled".into()));
    }
    Ok(environment)
}

pub(super) async fn signing_keys(
    State(state): State<ApiState>,
    Path(environment): Path<String>,
) -> Result<Json<Vec<SigningKeyView>>, ApiError> {
    run(state, move |store| {
        require_idp(&store, &environment)?;
        store.signing_key_views(&environment)
    })
    .await
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Rotate {
    grace_period: String,
    certificate_validity: String,
}

pub(super) async fn rotate_key(
    State(state): State<ApiState>,
    Path(environment): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Json<Vec<SigningKeyView>>, ApiError> {
    let input: Rotate = decode_optional(&headers, &bytes)?;
    let grace = parse_grace(&input.grace_period)?;
    let validity = CertificateValidity::parse(&input.certificate_validity)?;
    run(state, move |store| {
        require_idp(&store, &environment)?;
        store.rotate_signing_key(&environment, grace, validity)
    })
    .await
}

pub(super) async fn connection(
    State(state): State<ApiState>,
    Path(environment): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let host = state.host.clone();
    let tunnel = state.tunnel.clone();
    run(state, move |store| {
        let base = effective_base(&store, &tunnel, &host, &headers)?;
        store.connection_config(&environment, &base)
    })
    .await
}

pub(super) fn router(state: ApiState) -> Router {
    Router::new()
        .route("/apps/{environment_id}/config.json", get(connection))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            export_boundary,
        ))
        .with_state(state)
}
async fn export_boundary(State(state): State<ApiState>, request: Request, next: Next) -> Response {
    let mut response = if request
        .headers()
        .get(header::HOST)
        .and_then(|host| host.to_str().ok())
        != Some(&state.host)
    {
        ApiError(StatusCode::FORBIDDEN, "Invalid local host".into()).into_response()
    } else {
        next.run(request).await
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub(super) fn effective_base(
    store: &Store,
    tunnel: &crate::tunnel::Service,
    host: &str,
    headers: &HeaderMap,
) -> Result<String, Error> {
    let config = store.global_config()?;
    let proto = if config.trust_forwarded_headers {
        headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .filter(|value| ["http", "https"].contains(value))
            .unwrap_or("http")
    } else {
        "http"
    };
    tunnel.effective_base(&format!("{proto}://{host}"))
}
