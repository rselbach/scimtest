use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Default)]
pub struct Data {
    pub resources: HashMap<String, Value>,
    pub failures: HashMap<String, StatusCode>,
    pub logout_tokens: Vec<String>,
    next: usize,
}
pub struct Target {
    pub url: String,
    pub data: Arc<Mutex<Data>>,
    server: tokio::task::JoinHandle<()>,
}
impl Target {
    pub async fn new() -> Self {
        let data = Arc::new(Mutex::new(Data::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new().fallback(serve).with_state(data.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { url, data, server }
    }
    pub fn resource(&self, path: &str) -> Value {
        self.data
            .lock()
            .unwrap()
            .resources
            .get(path)
            .unwrap()
            .clone()
    }
    pub fn fail(&self, method: &str, collection: &str, status: StatusCode) {
        self.data
            .lock()
            .unwrap()
            .failures
            .insert(format!("{method} {collection}"), status);
    }
}
impl Drop for Target {
    fn drop(&mut self) {
        self.server.abort();
    }
}
async fn serve(State(data): State<Arc<Mutex<Data>>>, request: Request<Body>) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or_default().to_owned();
    let body = to_bytes(request.into_body(), 1 << 20).await.unwrap();
    let mut data = data.lock().unwrap();
    if path == "/backchannel" {
        let form: HashMap<String, String> = serde_urlencoded::from_bytes(&body).unwrap();
        data.logout_tokens.push(form["logout_token"].clone());
        return (
            data.failures
                .get("POST /backchannel")
                .copied()
                .unwrap_or(StatusCode::OK),
            "Greendale logout receiver",
        )
            .into_response();
    }
    let collection = format!(
        "/{}",
        path.trim_start_matches('/').split('/').next().unwrap()
    );
    if let Some(status) = data.failures.get(&format!("{method} {collection}")) {
        return (*status, "Greendale refused the request").into_response();
    }
    let (status, value) = match method.as_str() {
        "GET" if path == "/ServiceProviderConfig" => (
            StatusCode::OK,
            json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],"patch":{"supported":false},"filter":{"supported":true}}),
        ),
        "GET" if path == collection => {
            let query: HashMap<String, String> = serde_urlencoded::from_str(&query).unwrap();
            let filter = query
                .get("filter")
                .and_then(|filter| filter.strip_prefix("externalId eq \""))
                .map(|filter| filter.trim_end_matches('"'));
            let resources = data
                .resources
                .iter()
                .filter(|(path, value)| {
                    path.starts_with(&format!("{collection}/"))
                        && filter.is_none_or(|filter| value["externalId"] == filter)
                })
                .map(|(_, value)| value.clone())
                .collect::<Vec<_>>();
            (
                StatusCode::OK,
                json!({"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":resources.len(),"startIndex":1,"itemsPerPage":resources.len(),"Resources":resources}),
            )
        }
        "POST" => {
            let mut value: Value = serde_json::from_slice(&body).unwrap();
            data.next += 1;
            let id = format!("remote-{}", data.next);
            value["id"] = json!(id);
            data.resources
                .insert(format!("{collection}/{id}"), value.clone());
            (StatusCode::CREATED, value)
        }
        "PUT" if data.resources.contains_key(&path) => {
            let mut value: Value = serde_json::from_slice(&body).unwrap();
            value["id"] = json!(path.rsplit('/').next().unwrap());
            data.resources.insert(path, value.clone());
            (StatusCode::OK, value)
        }
        "GET" if data.resources.contains_key(&path) => {
            (StatusCode::OK, data.resources[&path].clone())
        }
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        status,
        [("Content-Type", "application/scim+json")],
        value.to_string(),
    )
        .into_response()
}
