pub(super) use super::chooser::chooser;
use super::*;
use crate::oidc::{Authorization, Identity, Logout, Parameters, ProtocolError};
use axum::{body::Bytes, extract::Query, http::HeaderMap, response::Html, routing::post};

pub(super) fn router(state: ApiState) -> Router {
    Router::new()
        .route(
            "/oidc/{slug}/.well-known/openid-configuration",
            get(discovery),
        )
        .route(
            "/.well-known/openid-configuration/oidc/{slug}",
            get(discovery),
        )
        .route("/oidc/{slug}/jwks", get(jwks))
        .route(
            "/oidc/{slug}/authorize",
            get(authorize_get).post(authorize_post),
        )
        .route("/oidc/{slug}/token", post(token))
        .route("/oidc/{slug}/userinfo", get(userinfo).post(userinfo))
        .route("/oidc/{slug}/introspect", post(introspect))
        .route("/oidc/{slug}/revoke", post(revoke))
        .route("/oidc/{slug}/logout", get(logout_get).post(logout_post))
        .route(
            "/oidc/{slug}/users/{oid}/getMemberObjects",
            post(member_objects),
        )
        .layer(DefaultBodyLimit::max(1 << 20))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            protocol_boundary,
        ))
        .with_state(state)
}
#[derive(Clone)]
struct Failure(String);

pub(super) async fn protocol_boundary(
    State(state): State<ApiState>,
    request: Request,
    next: Next,
) -> Response {
    if request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        != Some(&state.host)
    {
        return ApiError(StatusCode::FORBIDDEN, "Invalid local host".into()).into_response();
    }
    let (request, captured) = match super::traffic::capture_request(&state, request).await {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let path = request
        .uri()
        .path()
        .split('/')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut response = next.run(request).await;
    if let Some(failure) = response.extensions().get::<Failure>().cloned() {
        let identity = state.identity.clone();
        if let (Some(slug), Some(stage)) = (path.get(2), path.get(3)) {
            let (slug, stage) = (slug.clone(), stage.clone());
            let saml = path.get(1).is_some_and(|protocol| protocol == "saml");
            let stage = if saml && stage == "slo" {
                "logout".into()
            } else if stage == "users" && path.get(5).is_some_and(|part| part == "getMemberObjects")
            {
                "groups overage".into()
            } else {
                stage
            };
            let result = tokio::task::spawn_blocking(move || {
                if saml {
                    identity.record_saml_failure(&slug, &stage, &failure.0)
                } else {
                    identity.record_failure(&slug, &stage, &failure.0)
                }
            })
            .await;
            if let Err(error) = result {
                eprintln!("Record failed identity flow: {error}");
            }
        }
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    super::traffic::capture_response(state.diagnostics, captured, response).await
}
impl IntoResponse for ProtocolError {
    fn into_response(self) -> Response {
        let detail = format!("{}: {}", self.code, self.description);
        let mut response = (
            StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Json(json!({"error":self.code,"error_description":self.description})),
        )
            .into_response();
        response.extensions_mut().insert(Failure(detail));
        if self.basic_challenge {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"scimtest\", charset=\"UTF-8\""),
            );
        }
        if let Some(value) = self.retry_after
            && let Ok(value) = HeaderValue::from_str(&value)
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
}
pub(super) async fn protocol<T: Send + 'static>(
    state: ApiState,
    operation: impl FnOnce(Identity, Store) -> Result<T, ProtocolError> + Send + 'static,
) -> Result<T, ProtocolError> {
    tokio::task::spawn_blocking(move || operation(state.identity, state.store))
        .await
        .map_err(|_| ProtocolError {
            status: 500,
            ..ProtocolError::new("server_error", "identity operation failed")
        })?
}
fn issuer(state: &ApiState, headers: &HeaderMap, slug: &str) -> Result<String, ProtocolError> {
    Ok(format!(
        "{}/oidc/{slug}",
        keys::effective_base(&state.store, &state.tunnel, &state.host, headers)?
    ))
}
fn authorization(headers: &HeaderMap) -> String {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .into()
}
pub(super) fn cookie(headers: &HeaderMap, slug: &str) -> String {
    let name = format!("scimtest_chooser_{slug}");
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|value| value.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
        .unwrap_or_default()
}
pub(super) fn form(headers: &HeaderMap, bytes: &Bytes) -> Result<Parameters, ProtocolError> {
    if !bytes.is_empty()
        && headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_none_or(|value| {
                value.split(';').next().unwrap_or_default().trim()
                    != "application/x-www-form-urlencoded"
            })
    {
        return Err(ProtocolError::new(
            "invalid_request",
            "Content-Type must be application/x-www-form-urlencoded",
        ));
    }
    parameters(bytes)
}
pub(super) fn parameters(bytes: &[u8]) -> Result<Parameters, ProtocolError> {
    let pairs: Vec<(String, String)> = serde_urlencoded::from_bytes(bytes)
        .map_err(|_| ProtocolError::new("invalid_request", "invalid form encoding"))?;
    let mut values: Parameters = Parameters::new();
    for (key, value) in pairs {
        if key == "fault_tamper"
            && let Some(previous) = values.get_mut(&key)
        {
            previous.push(',');
            previous.push_str(&value);
        } else {
            values.entry(key).or_insert(value);
        }
    }
    Ok(values)
}
async fn discovery(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ProtocolError> {
    protocol(state.clone(), move |identity, _| {
        let directory = identity.directory(&slug)?;
        Ok(Json(crate::oidc::discovery(
            &directory.environment,
            &issuer(&state, &headers, &slug)?,
        )))
    })
    .await
}
async fn jwks(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
) -> Result<Json<Value>, ProtocolError> {
    protocol(state, move |identity, store| {
        let directory = identity.directory(&slug)?;
        let mut keys =
            store.published_signing_keys(&directory.environment.id, chrono::Utc::now())?;
        if identity.stale_jwks(&directory.environment.id)? && !keys.is_empty() {
            keys.remove(0);
        }
        Ok(Json(
            json!({"keys":keys.iter().map(|key| key.jwk()).collect::<Vec<_>>()}),
        ))
    })
    .await
}
async fn authorize_get(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
    Query(values): Query<Parameters>,
    headers: HeaderMap,
) -> Result<Response, ProtocolError> {
    authorize(state, slug, values, headers, false).await
}
async fn authorize_post(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
    Query(mut values): Query<Parameters>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response, ProtocolError> {
    values.extend(form(&headers, &bytes)?);
    authorize(state, slug, values, headers, true).await
}
async fn authorize(
    state: ApiState,
    slug: String,
    values: Parameters,
    headers: HeaderMap,
    post: bool,
) -> Result<Response, ProtocolError> {
    let session = cookie(&headers, &slug);
    let callback = format!(
        "http://{}/inspect/oidc/{slug}/playground/callback",
        state.host
    );
    let local = !state.tunneled;
    protocol(state, move |identity, _| {
        let result = identity.authorize(&slug, &values, &session, local, &callback, post)?;
        match result {
            Authorization::Redirect(uri) => {
                if let Ok(location) = url::Url::parse(&uri) {
                    let error = location
                        .query_pairs()
                        .find(|(key, _)| key == "error_description")
                        .map(|(_, value)| value.into_owned());
                    if let Some(error) = error {
                        identity.record_failure(&slug, "authorize", &error)?;
                    }
                }
                Ok(redirect(&uri))
            }
            Authorization::Code {
                redirect: uri,
                session,
                ..
            } => {
                let mut response = redirect(&uri);
                set_cookie(&mut response, &slug, &session, false);
                Ok(response)
            }
            Authorization::Chooser { directory, options } => {
                Ok(Html(chooser("OIDC sign-in", &directory, &values, &options)).into_response())
            }
        }
    })
    .await
}
fn redirect(uri: &str) -> Response {
    (StatusCode::FOUND, [(header::LOCATION, uri)]).into_response()
}
pub(super) fn set_cookie(response: &mut Response, slug: &str, session: &str, clear: bool) {
    let value = format!(
        "scimtest_chooser_{slug}={session}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax",
        if clear { 0 } else { 30 * 24 * 60 * 60 }
    );
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
}
macro_rules! form_endpoint {
    ($handler:ident, $method:ident) => {
        async fn $handler(
            State(state): State<ApiState>,
            Path(slug): Path<String>,
            headers: HeaderMap,
            bytes: Bytes,
        ) -> Result<Response, ProtocolError> {
            let values = form(&headers, &bytes)?;
            protocol(state.clone(), move |identity, _| {
                let result = identity.$method(
                    &slug,
                    &values,
                    &authorization(&headers),
                    &issuer(&state, &headers, &slug)?,
                )?;
                Ok(Json(result).into_response())
            })
            .await
        }
    };
}
async fn token(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response, ProtocolError> {
    let values = form(&headers, &bytes)?;
    let authorization = authorization(&headers);
    let identity = state.identity.clone();
    let requested_slug = slug.clone();
    let issuer = protocol(state.clone(), move |_, _| {
        issuer(&state, &headers, &requested_slug)
    })
    .await?;
    Ok(Json(
        identity
            .token_exchange(slug, values, authorization, issuer)
            .await?,
    )
    .into_response())
}
form_endpoint!(introspect, introspect);
async fn revoke(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<StatusCode, ProtocolError> {
    let values = form(&headers, &bytes)?;
    protocol(state, move |identity, _| {
        identity.revoke(&slug, &values, &authorization(&headers))?;
        Ok(StatusCode::OK)
    })
    .await
}
async fn userinfo(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, ProtocolError> {
    protocol(state.clone(), move |identity, _| {
        Ok(Json(identity.userinfo(
            &slug,
            &authorization(&headers),
            &issuer(&state, &headers, &slug)?,
        )?))
    })
    .await
}
async fn member_objects(
    State(state): State<ApiState>,
    Path((slug, oid)): Path<(String, String)>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    match protocol(state, move |identity, _| {
        identity.member_objects(&slug, &oid, &authorization(&headers), &body)
    })
    .await
    {
        Ok(value) => Json(value).into_response(),
        Err(error) => {
            let detail = format!("{}: {}", error.code, error.description);
            let mut response = (
                StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                Json(json!({"error":{"code":error.code,"message":error.description}})),
            )
                .into_response();
            response.extensions_mut().insert(Failure(detail));
            response
        }
    }
}
async fn logout_get(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
    Query(values): Query<Parameters>,
    headers: HeaderMap,
) -> Result<Response, ProtocolError> {
    logout(state, slug, values, headers, false).await
}
async fn logout_post(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Response, ProtocolError> {
    let values = form(&headers, &bytes)?;
    logout(state, slug, values, headers, true).await
}
async fn logout(
    state: ApiState,
    slug: String,
    values: Parameters,
    headers: HeaderMap,
    post: bool,
) -> Result<Response, ProtocolError> {
    protocol(state.clone(),move |identity,_| {
        let outcome = identity.logout(&slug,&values,&cookie(&headers,&slug),&issuer(&state,&headers,&slug)?,!state.tunneled,post)?;
        match outcome {
            Logout::Confirm { user } => Ok(Html(page("Sign out",&format!("<p>Sign out {}?</p><form method=post>{}<button name=confirm value=1>Sign out</button></form>",escape(&user),hidden(&values)))).into_response()),
            Logout::Complete { redirect:uri,clear_cookie } => {
                let mut response = uri.map(|uri| redirect(&uri)).unwrap_or_else(|| Html(page("Signed out","<p>Your session has ended.</p>")).into_response());
                if clear_cookie { set_cookie(&mut response,&slug,"",true); }
                Ok(response)
            }
        }
    }).await
}
pub(super) fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn hidden(values: &Parameters) -> String {
    values
        .iter()
        .filter(|(key, _)| {
            !["user_id", "login_identifier", "continue_session", "confirm"].contains(&key.as_str())
        })
        .map(|(key, value)| {
            format!(
                "<input type=hidden name=\"{}\" value=\"{}\">",
                escape(key),
                escape(value)
            )
        })
        .collect()
}
pub(super) fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{title} · scimtest</title><style>body{{font:14px system-ui;background:#f4f5f7;color:#222;margin:0;padding:64px 24px}}main{{max-width:440px;margin:auto;background:white;padding:32px;border:1px solid #dedfe3;border-radius:12px}}h1{{font-size:23px;margin:12px 0 24px}}label{{display:block;margin:16px 0}}input,select,button{{font:inherit;border:1px solid #d5d7dc;border-radius:6px;padding:10px;box-sizing:border-box}}input,select{{width:100%;margin-top:6px}}button{{background:#2563eb;color:white;margin:8px 8px 0 0;cursor:pointer}}.brand{{color:#697182;font-weight:600}}.secondary{{background:white;color:#333}}</style></head><body><main><div class=brand>scimtest</div><h1>{title}</h1>{body}</main></body></html>"#
    )
}
