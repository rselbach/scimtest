use super::*;
use crate::oidc::{Faults, Identity, Parameters, ProtocolError};
use axum::{body::Bytes, extract::Query, http::HeaderMap};

fn api_error(error: ProtocolError) -> ApiError {
    ApiError(
        StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        error.description,
    )
}
enum Capability {
    Directory,
    AnyIdp,
    Oidc,
    Saml,
}
async fn operation(
    state: ApiState,
    id: String,
    capability: Capability,
    operation: impl FnOnce(Identity, String) -> Result<Value, ProtocolError> + Send + 'static,
) -> Result<Json<Value>, ApiError> {
    tokio::task::spawn_blocking(move || {
        let environment = state.store.directory(&id)?.environment;
        let error = match capability {
            Capability::Oidc if !environment.settings.supports_oidc() => {
                Some("OIDC is not enabled")
            }
            Capability::Saml if !environment.settings.supports_saml() => {
                Some("SAML is not enabled")
            }
            Capability::AnyIdp
                if !environment.settings.supports_oidc()
                    && !environment.settings.supports_saml() =>
            {
                Some("environment has no OIDC or SAML configuration")
            }
            _ => None,
        };
        if let Some(error) = error {
            return Err(ApiError(StatusCode::BAD_REQUEST, error.into()));
        }
        operation(state.identity, id).map(Json).map_err(api_error)
    })
    .await
    .map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "identity operation failed".into(),
        )
    })?
}
pub(super) async fn oidc_tokens(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    operation(state, id, Capability::Oidc, |identity, id| {
        Ok(json!({"holders":identity.token_holders(&id)?}))
    })
    .await
}
pub(super) async fn revoke_oidc_tokens(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(values): Query<Parameters>,
) -> Result<Json<Value>, ApiError> {
    operation(state,id,Capability::Oidc,move |identity,id| Ok(json!({"revoked":identity.revoke_tokens(&id,values.get("user_id").map(String::as_str).unwrap_or_default())?}))).await
}
pub(super) async fn sessions(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    operation(state, id, Capability::AnyIdp, |identity, id| {
        Ok(json!({"sessions":identity.sessions(&id)?}))
    })
    .await
}
pub(super) async fn end_sessions(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(values): Query<Parameters>,
) -> Result<Json<Value>, ApiError> {
    operation(state,id,Capability::AnyIdp,move |identity,id| Ok(json!({"ended":identity.end_sessions(&id,values.get("session_id").map(String::as_str).unwrap_or_default())?}))).await
}
pub(super) async fn inspections(
    State(state): State<ApiState>,
    Path((id, protocol)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    match protocol.as_str() {
        "oidc" => {
            operation(state, id, Capability::Oidc, |identity, id| {
                Ok(json!(identity.inspections(&id)?))
            })
            .await
        }
        "saml" => {
            operation(state, id, Capability::Saml, |identity, id| {
                Ok(json!(identity.saml_inspections(&id)?))
            })
            .await
        }
        _ => Err(ApiError(
            StatusCode::NOT_FOUND,
            "protocol must be oidc or saml".into(),
        )),
    }
}

pub(super) async fn flows(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    operation(state, id, Capability::Directory, |identity, id| {
        Ok(json!(identity.flows(&id)?))
    })
    .await
}
fn fault_response(faults: Faults) -> Value {
    json!({"active":faults.active(),"id_token_ttl":faults.id_token_ttl.as_deref().unwrap_or("0s"),"id_token_ttl_set":faults.id_token_ttl.is_some(),
        "assertion_ttl":faults.assertion_ttl.as_deref().unwrap_or("0s"),"assertion_ttl_set":faults.assertion_ttl.is_some(),"clock_skew":faults.clock_skew.as_deref().unwrap_or("0s"),"break_signature":faults.break_signature,
        "drop_claims":if faults.drop_claims.is_empty() { Value::Null } else { json!(faults.drop_claims) },"token_error":faults.token_error,"saml_status":faults.saml_status_value().unwrap_or_default(),
        "tamper":if faults.tamper.is_empty() { Value::Null } else { json!(faults.tamper) }})
}
pub(super) async fn fault_get(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    operation(state, id, Capability::AnyIdp, |identity, id| {
        Ok(fault_response(identity.faults(&id)?))
    })
    .await
}
pub(super) async fn fault_put(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Json<Value>, ApiError> {
    let faults = decode_optional::<Faults>(&headers, &bytes)?.normalized()?;
    if !faults.active() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "at least one fault is required".into(),
        ));
    }
    operation(state, id, Capability::AnyIdp, move |identity, id| {
        identity.arm_faults(&id, faults.clone())?;
        Ok(fault_response(faults))
    })
    .await
}
pub(super) async fn fault_delete(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    tokio::task::spawn_blocking(move || {
        state.store.directory(&id)?;
        state.identity.disarm_faults(&id).map_err(api_error)?;
        Ok::<_, ApiError>(StatusCode::NO_CONTENT)
    })
    .await
    .map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "identity operation failed".into(),
        )
    })?
}

pub(super) async fn playground(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Json<Value>, ApiError> {
    let input: crate::oidc::PlaygroundInput = decode_optional(&headers, &bytes)?;
    crate::oidc::playground(state.store, id, format!("http://{}", state.host), input)
        .await
        .map(Json)
        .map_err(api_error)
}
