use super::*;
use crate::oidc::{Parameters, ProtocolError, SamlAuthorization, SamlLogout};
use axum::{
    body::Bytes,
    extract::{Query, RawQuery},
    http::HeaderMap,
    response::Html,
};

pub(super) fn router(state: ApiState) -> Router {
    let router = Router::new()
        .route("/saml/{slug}/metadata", get(metadata))
        .route("/saml/{slug}/certificate.pem", get(certificate))
        .route("/saml/{slug}/sso", get(sso_get).post(sso_post))
        .route("/saml/{slug}/slo", get(slo_get).post(slo_post));
    let router = if state.tunneled {
        router
    } else {
        router.route("/saml/{slug}/continue/{ticket}", get(delivery))
    };
    router
        .layer(DefaultBodyLimit::max(1 << 20))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            oidc::protocol_boundary,
        ))
        .with_state(state)
}
async fn delivery(
    State(state): State<ApiState>,
    Path((slug, ticket)): Path<(String, String)>,
) -> Result<Response, ProtocolError> {
    oidc::protocol(state, move |identity, _| {
        let message = identity.saml_delivery(&slug, &ticket)?;
        Ok(outbound(message))
    })
    .await
}
pub(super) fn outbound(message: crate::saml::OutboundMessage) -> Response {
    if message.binding == crate::saml::REDIRECT_BINDING {
        return (StatusCode::FOUND, [(header::LOCATION, message.url)]).into_response();
    }
    Html(post_form(
        &message.destination,
        message.param,
        &message.encoded,
        &message.relay_state,
    ))
    .into_response()
}
async fn metadata(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
    Query(query): Query<Parameters>,
    headers: HeaderMap,
) -> Result<Response, ProtocolError> {
    oidc::protocol(state.clone(), move |_, store| {
        let directory = store.directory_by_slug(&slug)?;
        if !directory.environment.settings.supports_saml() {
            return Err(Error::NotFound("SAML environment").into());
        }
        let base = keys::effective_base(&store, &state.tunnel, &state.host, &headers)?;
        let xml = crate::saml::metadata(&store, &directory.environment, &base)?;
        let mut response = (
            [(
                header::CONTENT_TYPE,
                "application/samlmetadata+xml; charset=utf-8",
            )],
            xml,
        )
            .into_response();
        if query.get("download").is_some_and(|value| value == "1") {
            response.headers_mut().insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!(
                    "attachment; filename=\"scimtest-{slug}-idp-metadata.xml\""
                ))
                .map_err(|_| ProtocolError::new("server_error", "invalid filename"))?,
            );
        }
        Ok(response)
    })
    .await
}
async fn certificate(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
) -> Result<Response, ProtocolError> {
    oidc::protocol(state, move |_, store| {
        let directory = store.directory_by_slug(&slug)?;
        if !directory.environment.settings.supports_saml() {
            return Err(Error::NotFound("SAML environment").into());
        }
        let key = store.active_signing_key(&directory.environment.id)?;
        Ok((
            [
                (header::CONTENT_TYPE, "application/x-pem-file".to_owned()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"scimtest-{slug}.pem\""),
                ),
            ],
            key.stored.certificate_pem,
        )
            .into_response())
    })
    .await
}
async fn sso_get(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Result<Response, ProtocolError> {
    let query = query.unwrap_or_default();
    let values = oidc::parameters(query.as_bytes())?;
    sso(state, slug, values, headers, query, false, false).await
}
async fn sso_post(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response, ProtocolError> {
    let query = query.unwrap_or_default();
    let original = oidc::parameters(query.as_bytes())?;
    let mut values = original.clone();
    values.extend(oidc::form(&headers, &bytes)?);
    if let Some(message) = original
        .get("SAMLRequest")
        .filter(|value| !value.is_empty())
    {
        values.insert("SAMLRequest".into(), message.clone());
        values.remove("RelayState");
        if let Some(relay) = original.get("RelayState") {
            values.insert("RelayState".into(), relay.clone());
        }
    }
    sso(state, slug, values, headers, query, true, false).await
}
#[allow(clippy::too_many_arguments)]
async fn sso(
    state: ApiState,
    slug: String,
    values: Parameters,
    headers: HeaderMap,
    query: String,
    post: bool,
    json_response: bool,
) -> Result<Response, ProtocolError> {
    oidc::protocol(state.clone(),move |identity,store| {
        let base = keys::effective_base(&store,&state.tunnel,&state.host,&headers)?;
        let outcome = identity.saml_sign_in(&slug,&values,&oidc::cookie(&headers,&slug),&base,&query,post)?;
        match outcome {
            SamlAuthorization::Chooser { directory,options } if !json_response=>Ok(Html(oidc::chooser("SAML sign-in",&directory,&values,&options)).into_response()),
            SamlAuthorization::Chooser { .. }=>Err(ProtocolError::new("invalid_request","active user is required")),
            SamlAuthorization::Response { acs_url,saml_response,relay_state,session }=>{
                let mut response = if json_response { Json(json!({"acs_url":acs_url,"saml_response":saml_response,"relay_state":relay_state})).into_response() }
                    else { Html(post_back(&acs_url,&saml_response,&relay_state)).into_response() };
                if !session.is_empty() { oidc::set_cookie(&mut response,&slug,&session,false); }
                Ok(response)
            }
        }
    }).await
}
fn post_back(target: &str, response: &str, relay: &str) -> String {
    post_form(target, "SAMLResponse", response, relay)
}
fn post_form(target: &str, param: &str, response: &str, relay: &str) -> String {
    let relay = if relay.is_empty() {
        String::new()
    } else {
        format!(
            "<input type=\"hidden\" name=\"RelayState\" value=\"{}\">",
            oidc::escape(relay)
        )
    };
    format!(
        "<!doctype html><html><head><meta charset=utf-8><title>Continue</title></head><body><form method=post action=\"{}\"><input type=\"hidden\" name=\"{param}\" value=\"{}\">{relay}<noscript><button type=submit>Continue</button></noscript></form><script>document.forms[0].submit()</script></body></html>",
        oidc::escape(target),
        oidc::escape(response)
    )
}

async fn slo_get(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Result<Response, ProtocolError> {
    let query = query.unwrap_or_default();
    let values = oidc::parameters(query.as_bytes())?;
    slo(state, slug, values, headers, query, false).await
}
async fn slo_post(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response, ProtocolError> {
    let values = oidc::form(&headers, &bytes)?;
    slo(
        state,
        slug,
        values,
        headers,
        query.unwrap_or_default(),
        true,
    )
    .await
}
async fn slo(
    state: ApiState,
    slug: String,
    values: Parameters,
    headers: HeaderMap,
    query: String,
    post: bool,
) -> Result<Response, ProtocolError> {
    oidc::protocol(state.clone(),move |identity,store| {
        let base = keys::effective_base(&store,&state.tunnel,&state.host,&headers)?;
        match identity.saml_logout(&slug,&values,&oidc::cookie(&headers,&slug),&base,&query,post)? {
            SamlLogout::Outbound { message,clear_cookie } => {
                let mut response = if message.binding == crate::saml::REDIRECT_BINDING {
                    (StatusCode::FOUND,[(header::LOCATION,message.url)]).into_response()
                } else {
                    Html(post_form(&message.destination,message.param,&message.encoded,&message.relay_state)).into_response()
                };
                if clear_cookie { oidc::set_cookie(&mut response,&slug,"",true); }
                Ok(response)
            }
            SamlLogout::Complete { user,detail } => Ok(Html(format!("<!doctype html><html><head><meta charset=utf-8><title>Signed out</title></head><body><h1>Signed out</h1><p>{}</p><p>{}</p></body></html>",oidc::escape(&user),oidc::escape(&detail))).into_response())
        }
    }).await
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct LogoutInput {
    session_id: String,
    binding: String,
}
pub(super) async fn logout(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Json<Value>, ApiError> {
    let input: LogoutInput = decode_optional(&headers, &bytes)?;
    let response = oidc::protocol(state.clone(), move |identity, store| {
        let base = keys::effective_base(&store, &state.tunnel, &state.host, &headers)?;
        Ok(Json(
            identity
                .start_saml_logout(&id, &input.session_id, &input.binding, &base)?
                .api_response(),
        ))
    })
    .await
    .map_err(|error| {
        ApiError(
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            error.description,
        )
    })?;
    Ok(response)
}
pub(super) async fn logouts(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    oidc::protocol(state, move |identity, _| {
        Ok(Json(json!({"logouts":identity.saml_logouts(&id)?})))
    })
    .await
    .map_err(|error| {
        ApiError(
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            error.description,
        )
    })
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SignIn {
    user_id: String,
    login_identifier: String,
    relay_state: String,
    saml_request: String,
    sig_alg: String,
    signature: String,
    redirect_query: String,
    authn_strength: String,
}
pub(super) async fn sign_in(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response, ApiError> {
    let input: SignIn = decode_optional(&headers, &bytes)?;
    let Json(environment) = run(state.clone(), move |store| {
        let environment = store.directory(&id)?.environment;
        if !environment.settings.supports_saml() {
            return Err(Error::Validation("SAML is not enabled".into()));
        }
        Ok(environment)
    })
    .await?;
    let mut values = Parameters::from([
        ("user_id".into(), input.user_id.clone()),
        ("login_identifier".into(), input.login_identifier.clone()),
        ("RelayState".into(), input.relay_state.clone()),
    ]);
    if !input.redirect_query.is_empty() {
        if !input.saml_request.is_empty()
            || !input.sig_alg.is_empty()
            || !input.signature.is_empty()
            || !input.relay_state.is_empty()
        {
            return Err(ApiError(StatusCode::BAD_REQUEST,"redirect_query cannot be combined with saml_request, sig_alg, signature, or relay_state".into()));
        }
        values = oidc::parameters(input.redirect_query.as_bytes())
            .map_err(|error| ApiError(StatusCode::BAD_REQUEST, error.description))?;
        if values.get("SAMLRequest").is_none_or(String::is_empty) {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                "redirect_query must contain SAMLRequest".into(),
            ));
        }
        values.insert("user_id".into(), input.user_id);
        values.insert("login_identifier".into(), input.login_identifier);
    }
    for (name, value) in [
        ("SAMLRequest", input.saml_request),
        ("SigAlg", input.sig_alg),
        ("Signature", input.signature),
    ] {
        if !value.is_empty() {
            values.insert(name.into(), value);
        }
    }
    values.insert("authn_strength".into(), input.authn_strength);
    sso(
        state,
        environment.slug,
        values,
        headers,
        input.redirect_query,
        true,
        true,
    )
    .await
    .map_err(|error| {
        ApiError(
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            error.description,
        )
    })
}
