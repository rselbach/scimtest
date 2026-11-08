use super::*;
use crate::oidc::{Authorization, Parameters};
use axum::{body::Bytes, http::HeaderMap};

#[derive(Default, Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
struct Input {
    user_id: String,
    login_identifier: String,
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    scope: String,
    nonce: String,
    code_challenge: String,
    code_challenge_method: String,
    acr_values: String,
    authn_strength: String,
}
pub(super) async fn authorize(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response, ApiError> {
    let mut input: Input = decode_optional(&headers, &bytes)?;
    tokio::task::spawn_blocking(move || {
        let environment = state.store.directory(&id)?.environment;
        if !environment.settings.supports_oidc() {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                "OIDC is not enabled".into(),
            ));
        }
        if input.client_id.is_empty() {
            input.client_id = environment.settings.oidc_client_id;
        }
        if input.response_type.is_empty() {
            input.response_type = "code".into();
        }
        let values: Parameters =
            serde_json::from_value(serde_json::to_value(input).map_err(Error::from)?)
                .map_err(Error::from)?;
        let outcome = state
            .identity
            .authorize(
                &environment.slug,
                &values,
                &oidc::cookie(&headers, &environment.slug),
                true,
                "",
                true,
            )
            .map_err(|error| ApiError(StatusCode::BAD_REQUEST, error.description))?;
        match outcome {
            Authorization::Code {
                code,
                redirect,
                state,
                session,
            } => {
                let mut response = Json(json!({"code":code,"redirect_uri":redirect,"state":state}))
                    .into_response();
                oidc::set_cookie(&mut response, &environment.slug, &session, false);
                Ok(response)
            }
            Authorization::Redirect(uri) => {
                let uri = url::Url::parse(&uri).map_err(|_| {
                    ApiError(StatusCode::BAD_REQUEST, "invalid authorize request".into())
                })?;
                let description = uri
                    .query_pairs()
                    .find(|(key, _)| key == "error_description")
                    .map(|(_, value)| value.into_owned())
                    .unwrap_or_else(|| "invalid authorize request".into());
                Err(ApiError(StatusCode::BAD_REQUEST, description))
            }
            Authorization::Chooser { .. } => Err(ApiError(
                StatusCode::BAD_REQUEST,
                "active user is required".into(),
            )),
        }
    })
    .await
    .map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "authorization failed".into(),
        )
    })?
}
