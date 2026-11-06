use super::*;
use crate::oidc::Parameters;
use axum::{
    extract::{Form, Query},
    http::HeaderMap,
    response::Html,
    routing::post,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::Duration;

mod view;

pub(super) fn router(state: ApiState) -> Router {
    Router::new()
        .route("/inspect/oidc/{slug}/playground", get(start))
        .route("/inspect/oidc/{slug}/playground/callback", get(callback))
        .route("/inspect/oidc/{slug}/playground/refresh", post(refresh))
        .route("/inspect/oidc/{slug}", get(inspect))
        .route("/inspect/oidc/{slug}/revoke", post(revoke))
        .route("/inspect/oidc/{slug}/sessions/end", post(end_session))
        .layer(DefaultBodyLimit::max(1 << 20))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            lifecycle::boundary,
        ))
        .with_state(state)
}

async fn environment(state: &ApiState, slug: String) -> Result<Environment, ApiError> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || {
        let environment = store.directory_by_slug(&slug)?.environment;
        if !environment.settings.supports_oidc() {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                "OIDC is not enabled".into(),
            ));
        }
        Ok(environment)
    })
    .await
    .map_err(|error| ApiError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?
}

fn random_secret(length: usize) -> String {
    let mut bytes = vec![0; length];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

async fn start(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
    Query(values): Query<Vec<(String, String)>>,
) -> Result<Response, ApiError> {
    let environment = environment(&state, slug).await?;
    let settings = &environment.settings;
    if settings.oidc_client_id.trim().is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "set an OIDC client ID for this environment before using the playground".into(),
        ));
    }
    if !settings.oidc_public_client && settings.oidc_client_secret.trim().is_empty() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "set an OIDC client secret for this environment before using the playground".into(),
        ));
    }
    let base = format!("http://{}", state.host);
    let slug = &environment.slug;
    let callback = format!("{base}/inspect/oidc/{slug}/playground/callback");
    let nonce = random_secret(16);
    let flow_state = random_secret(16);
    let verifier = if settings.oidc_public_client {
        random_secret(32)
    } else {
        String::new()
    };
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.extend_pairs([
        ("response_type", "code"),
        ("client_id", settings.oidc_client_id.as_str()),
        ("redirect_uri", &callback),
        ("scope", "openid profile email groups offline_access"),
        ("state", &flow_state),
        ("nonce", &nonce),
    ]);
    if settings.oidc_public_client {
        query.append_pair(
            "code_challenge",
            &URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
        );
        query.append_pair("code_challenge_method", "S256");
    }
    query.extend_pairs(values.iter().filter(|(key, _)| key.starts_with("fault_")));
    let mut response = (
        StatusCode::FOUND,
        [(
            header::LOCATION,
            format!("{base}/oidc/{slug}/authorize?{}", query.finish()),
        )],
    )
        .into_response();
    let cookie = format!(
        "scimtest_playground_{slug}={flow_state}|{nonce}|{verifier}; Path=/inspect/oidc/{slug}; Max-Age=600; HttpOnly; SameSite=Lax"
    );
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie)
            .map_err(|error| ApiError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?,
    );
    Ok(response)
}

#[derive(Default)]
struct ResultPage {
    error: String,
    code: String,
    state: String,
    token_status: String,
    token_body: String,
    id_token: String,
    id_header: String,
    id_claims: String,
    access_header: String,
    access_claims: String,
    refresh_token: String,
    userinfo: String,
    refreshed: bool,
    scope: String,
    previous_claims: String,
}

async fn callback(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Query(values): Query<Parameters>,
) -> Result<Html<String>, ApiError> {
    let environment = environment(&state, slug).await?;
    let mut result = ResultPage::default();
    let value = |key: &str| values.get(key).map(String::as_str).unwrap_or_default();
    if !value("error").is_empty() {
        result.error = format!("{}: {}", value("error"), value("error_description"));
        return Ok(Html(view::result(&environment, &result)));
    }
    let cookie_name = format!("scimtest_playground_{}", environment.slug);
    let cookie = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|header| header.to_str().ok())
        .flat_map(|header| header.split(';'))
        .filter_map(|cookie| cookie.trim().split_once('='))
        .find(|(name, _)| *name == cookie_name)
        .map(|(_, value)| value);
    let verifier = match cookie {
        None => {
            result.error = "playground session expired; start the test sign-in again".into();
            None
        }
        Some(cookie) => {
            let parts = cookie.splitn(3, '|').collect::<Vec<_>>();
            if parts.len() != 3 || parts[0].is_empty() || parts[0] != value("state") {
                result.error = "state did not match the playground session".into();
                None
            } else {
                Some(parts[2])
            }
        }
    };
    if let Some(verifier) = verifier {
        result.code = value("code").into();
        result.state = value("state").into();
        if result.code.is_empty() {
            result.error = "authorization response carried no code".into();
        } else {
            let mut form = Parameters::from([
                ("grant_type".into(), "authorization_code".into()),
                ("code".into(), result.code.clone()),
                (
                    "redirect_uri".into(),
                    format!(
                        "http://{}/inspect/oidc/{}/playground/callback",
                        state.host, environment.slug
                    ),
                ),
            ]);
            if environment.settings.oidc_public_client {
                form.insert("code_verifier".into(), verifier.into());
            }
            redeem(&state, &environment, form, &mut result).await;
        }
    }
    Ok(Html(view::result(&environment, &result)))
}

async fn refresh(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
    Form(values): Form<Parameters>,
) -> Result<Html<String>, ApiError> {
    let environment = environment(&state, slug).await?;
    let mut result = ResultPage {
        refreshed: true,
        scope: values
            .get("scope")
            .map(|value| value.trim().to_owned())
            .unwrap_or_default(),
        previous_claims: decode_jwt(
            values
                .get("previous_id_token")
                .map(String::as_str)
                .unwrap_or_default(),
        )
        .1,
        ..Default::default()
    };
    let mut form = Parameters::from([
        ("grant_type".into(), "refresh_token".into()),
        (
            "refresh_token".into(),
            values.get("refresh_token").cloned().unwrap_or_default(),
        ),
    ]);
    if !result.scope.is_empty() {
        form.insert("scope".into(), result.scope.clone());
    }
    redeem(&state, &environment, form, &mut result).await;
    Ok(Html(view::result(&environment, &result)))
}

async fn redeem(
    state: &ApiState,
    environment: &Environment,
    form: Parameters,
    result: &mut ResultPage,
) {
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        exchange(state, environment, form, result),
    )
    .await;
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(error)) => result.error = error,
        Err(_) => result.error = "playground token exchange timed out".into(),
    }
}

async fn exchange(
    state: &ApiState,
    environment: &Environment,
    mut form: Parameters,
    result: &mut ResultPage,
) -> Result<(), String> {
    let settings = &environment.settings;
    let issuer = format!("http://{}/oidc/{}", state.host, environment.slug);
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|error| error.to_string())?;
    if settings.oidc_public_client {
        form.insert("client_id".into(), settings.oidc_client_id.clone());
    }
    let mut request = client.post(format!("{issuer}/token")).form(&form);
    if !settings.oidc_public_client {
        let encode = |value: &str| {
            url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
        };
        request = request.basic_auth(
            encode(&settings.oidc_client_id),
            Some(encode(&settings.oidc_client_secret)),
        );
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("token request failed: {error}"))?;
    let status = response.status();
    result.token_status = format!(
        "{} {}",
        status.as_u16(),
        status.canonical_reason().unwrap_or_default()
    );
    result.token_body = pretty(&read(response).await?);
    if status != reqwest::StatusCode::OK {
        return Ok(());
    }
    let token: Value = serde_json::from_str(&result.token_body)
        .map_err(|error| format!("decode token response: {error}"))?;
    result.id_token = token["id_token"].as_str().unwrap_or_default().into();
    (result.id_header, result.id_claims) = decode_jwt(&result.id_token);
    (result.access_header, result.access_claims) =
        decode_jwt(token["access_token"].as_str().unwrap_or_default());
    result.refresh_token = token["refresh_token"].as_str().unwrap_or_default().into();
    let access = token["access_token"].as_str().unwrap_or_default();
    if !access.is_empty() {
        let response = client
            .get(format!("{issuer}/userinfo"))
            .bearer_auth(access)
            .send()
            .await
            .map_err(|error| format!("userinfo request failed: {error}"))?;
        result.userinfo = pretty(&read(response).await?);
    }
    Ok(())
}

async fn read(mut response: reqwest::Response) -> Result<String, String> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| error.to_string())? {
        if body.len() + chunk.len() > 1 << 20 {
            return Err("response body too large".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn pretty(value: &str) -> String {
    serde_json::from_str::<Value>(value)
        .and_then(|value| serde_json::to_string_pretty(&value))
        .unwrap_or_else(|_| value.into())
}

fn decode_jwt(token: &str) -> (String, String) {
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Default::default();
    }
    let decode = |part| {
        URL_SAFE_NO_PAD
            .decode(part)
            .ok()
            .map(|raw| pretty(&String::from_utf8_lossy(&raw)))
            .unwrap_or_default()
    };
    (decode(parts[0]), decode(parts[1]))
}

async fn inspect(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
) -> Result<Html<String>, ApiError> {
    let environment = environment(&state, slug).await?;
    oidc::protocol(state, move |identity, _| {
        Ok(Html(view::inspector(
            &environment,
            &identity.sessions(&environment.id)?,
            &identity.token_holders(&environment.id)?,
            &identity.inspections(&environment.id)?,
            &identity.flows(&environment.id)?,
        )))
    })
    .await
    .map_err(|error| {
        ApiError(
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            error.description,
        )
    })
}

async fn revoke(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
    Form(values): Form<Parameters>,
) -> Result<Response, ApiError> {
    control(state, slug, values, false).await
}
async fn end_session(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
    Form(values): Form<Parameters>,
) -> Result<Response, ApiError> {
    control(state, slug, values, true).await
}
async fn control(
    state: ApiState,
    slug: String,
    values: Parameters,
    sessions: bool,
) -> Result<Response, ApiError> {
    let environment = environment(&state, slug).await?;
    oidc::protocol(state, move |identity, _| {
        if sessions {
            identity.end_sessions(
                &environment.id,
                values
                    .get("session_id")
                    .map(String::as_str)
                    .unwrap_or_default(),
            )?;
        } else {
            identity.revoke_tokens(
                &environment.id,
                values
                    .get("user_id")
                    .map(String::as_str)
                    .unwrap_or_default(),
            )?;
        }
        Ok((
            StatusCode::SEE_OTHER,
            [(
                header::LOCATION,
                format!("/inspect/oidc/{}", environment.slug),
            )],
        )
            .into_response())
    })
    .await
    .map_err(|error| {
        ApiError(
            StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            error.description,
        )
    })
}
