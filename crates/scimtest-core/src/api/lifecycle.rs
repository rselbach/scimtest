use super::*;
use crate::oidc::{JoinerInput, LifecycleRun, MoverInput, ProtocolError};
use axum::{
    body::Bytes,
    extract::{Form, Query},
    http::HeaderMap,
    response::Html,
};

fn error(mut error: ProtocolError) -> ApiError {
    if error.description.ends_with(" not found") {
        error.status = 404;
    }
    ApiError(
        StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        error.description,
    )
}
pub(super) async fn list(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let base = format!("http://{}", state.host);
    oidc::protocol(state, move |identity, _| {
        let runs = identity
            .lifecycle_runs(&id)?
            .into_iter()
            .map(|run| run.with_browser_urls(&base, &id))
            .collect::<Vec<_>>();
        Ok(Json(json!({"runs":runs})))
    })
    .await
    .map_err(error)
}
pub(super) async fn get_run(
    State(state): State<ApiState>,
    Path((id, run)): Path<(String, String)>,
) -> Result<Json<LifecycleRun>, ApiError> {
    let base = format!("http://{}", state.host);
    oidc::protocol(state, move |identity, _| {
        Ok(Json(
            identity
                .lifecycle_run(&id, &run)?
                .with_browser_urls(&base, &id),
        ))
    })
    .await
    .map_err(error)
}
enum Start {
    Joiner(JoinerInput),
    Mover(MoverInput),
    Leaver(String),
}
async fn start(state: ApiState, id: String, input: Start) -> Result<impl IntoResponse, ApiError> {
    let base = format!("http://{}", state.host);
    let scim = state.scim.clone();
    let run = oidc::protocol(state, move |identity, _| {
        let run = match input {
            Start::Joiner(input) => identity.start_joiner(&id, input, scim),
            Start::Mover(input) => identity.start_mover(&id, input, scim),
            Start::Leaver(user) => identity.start_leaver(&id, &user, scim),
        }?;
        Ok(Json(run.with_browser_urls(&base, &id)))
    })
    .await
    .map_err(error)?;
    Ok((StatusCode::ACCEPTED, run))
}
pub(super) async fn joiner(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    start(state, id, Start::Joiner(decode_optional(&headers, &body)?)).await
}
pub(super) async fn mover(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    start(state, id, Start::Mover(decode_optional(&headers, &body)?)).await
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Leaver {
    user_id: String,
}
pub(super) async fn leaver(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    let input: Leaver = decode_optional(&headers, &body)?;
    start(state, id, Start::Leaver(input.user_id)).await
}

pub(super) fn router(state: ApiState) -> Router {
    Router::new()
        .route("/", axum::routing::get(browser))
        .route("/inspect/lifecycle/{slug}", axum::routing::get(inspect))
        .route(
            "/inspect/lifecycle/{slug}/saml-logout",
            axum::routing::post(logout),
        )
        .layer(DefaultBodyLimit::max(1 << 20))
        .layer(middleware::from_fn_with_state(state.clone(), boundary))
        .with_state(state)
}
pub(super) async fn boundary(
    State(state): State<ApiState>,
    request: Request,
    next: Next,
) -> Response {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|host| host.to_str().ok());
    let origin = request.headers().get(header::ORIGIN);
    let mut response = if host != Some(&state.host) {
        ApiError(StatusCode::FORBIDDEN, "Invalid local host".into()).into_response()
    } else if request.method() != Method::GET
        && request.method() != Method::HEAD
        && origin
            .is_some_and(|origin| origin.as_bytes() != format!("http://{}", state.host).as_bytes())
    {
        ApiError(
            StatusCode::FORBIDDEN,
            "Cross-origin mutation is not allowed".into(),
        )
        .into_response()
    } else {
        next.run(request).await
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
async fn inspect(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
) -> Result<Response, ApiError> {
    oidc::protocol(state, move |_, store| {
        let id = store.directory_by_slug(&slug)?.environment.id;
        Ok((
            StatusCode::SEE_OTHER,
            [(
                header::LOCATION,
                format!("/?environment={id}&tab=lifecycle"),
            )],
        )
            .into_response())
    })
    .await
    .map_err(error)
}
async fn browser(
    State(state): State<ApiState>,
    Query(query): Query<crate::oidc::Parameters>,
) -> Result<Html<String>, ApiError> {
    if query.get("tab").is_none_or(|tab| tab != "lifecycle") {
        return Ok(Html("<!doctype html><meta charset=utf-8><title>scimtest</title><h1>scimtest</h1><p>Use the scimtest desktop window to manage environments.</p>".into()));
    }
    let id = query.get("environment").cloned().unwrap_or_default();
    oidc::protocol(state,move |identity,store| {
        let environment = store.directory(&id)?.environment;
        let runs = identity.lifecycle_runs(&id)?;
        let refresh = if runs.iter().any(|run| run.status == "running") { "<meta http-equiv=refresh content=1>" } else { "" };
        let mut html = format!("<!doctype html><html><head><meta charset=utf-8><title>Lifecycle · scimtest</title>{refresh}<style>body{{font:14px system-ui;background:#f3f3f3;color:#252525;max-width:900px;margin:40px auto}}article{{background:white;border:1px solid #ccc;border-radius:8px;padding:20px;margin:16px 0}}section{{padding:12px 0;border-top:1px solid #ddd}}button{{background:#0088ff;color:white;border:0;border-radius:5px;padding:8px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}small{{color:#666}}</style></head><body><h1>Lifecycle</h1><p>{}</p>",oidc::escape(&environment.name));
        if let Some(error) = query.get("error") { html.push_str(&format!("<p role=alert>{}</p>",oidc::escape(error))); }
        for run in runs {
            html.push_str(&format!("<article id=\"lifecycle-run-{}\"><h2>{}: {}</h2><p>{}</p>",run.id,oidc::escape(&run.kind),oidc::escape(&run.user),oidc::escape(&run.status)));
            for step in run.steps {
                html.push_str(&format!("<section><strong>{}</strong> <small>{}</small><p>{}</p>",oidc::escape(&step.title),oidc::escape(&step.status.replace('_'," ")),oidc::escape(&step.detail)));
                if step.can_send_logout() {
                    html.push_str(&format!("<form method=post action=\"/inspect/lifecycle/{}/saml-logout\"><input type=hidden name=run_id value=\"{}\"><input type=hidden name=step_id value=\"{}\"><select name=binding aria-label=Binding><option value=redirect>HTTP-Redirect</option><option value=post>HTTP-POST</option></select> <button>Send LogoutRequest</button></form>",oidc::escape(&environment.slug),run.id,oidc::escape(&step.id)));
                }
                for message in step.messages { html.push_str(&format!("<pre>{}\n{}\n{}\n{}</pre>",oidc::escape(&message.sent),oidc::escape(&message.to),oidc::escape(&message.body),oidc::escape(&message.response))); }
                html.push_str("</section>");
            }
            html.push_str("</article>");
        }
        html.push_str("</body></html>");
        Ok(Html(html))
    }).await.map_err(error)
}
async fn logout(
    State(state): State<ApiState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Form(values): Form<crate::oidc::Parameters>,
) -> Result<Response, ApiError> {
    oidc::protocol(state.clone(), move |identity, store| {
        let environment = store.directory_by_slug(&slug)?.environment;
        let base = keys::effective_base(&store, &state.tunnel, &state.host, &headers)?;
        let run = values.get("run_id").map(String::as_str).unwrap_or_default();
        let result = identity.lifecycle_saml_logout(
            &environment.id,
            run,
            values
                .get("step_id")
                .map(String::as_str)
                .unwrap_or_default(),
            values
                .get("binding")
                .map(String::as_str)
                .unwrap_or_default(),
            &base,
        );
        match result {
            Ok(message) => Ok(saml::outbound(message)),
            Err(error) => {
                let query = url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs([
                        ("environment", environment.id.as_str()),
                        ("tab", "lifecycle"),
                        ("error", error.description.as_str()),
                    ])
                    .finish();
                Ok((
                    StatusCode::SEE_OTHER,
                    [(header::LOCATION, format!("/?{query}#lifecycle-run-{run}"))],
                )
                    .into_response())
            }
        }
    })
    .await
    .map_err(error)
}
