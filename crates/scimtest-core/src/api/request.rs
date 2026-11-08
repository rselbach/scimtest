use super::*;
use axum::body::Body;

pub(super) async fn validate_body(request: Request, next: Next) -> Response {
    let Some(path) = request
        .extensions()
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_owned())
    else {
        return next.run(request).await;
    };
    let route = routes()
        .into_iter()
        .find(|route| route["path"] == path && route["method"] == request.method().as_str());
    let Some(route) = route.filter(|_| !matches!(*request.method(), Method::GET | Method::HEAD))
    else {
        return next.run(request).await;
    };
    let (parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, 25 << 20).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return ApiError(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid JSON: http: request body too large".into(),
            )
            .into_response();
        }
    };
    let fields = route["fields"].as_array().cloned().unwrap_or_default();
    if bytes.is_empty() && (fields.is_empty() || path.ends_with("/signing-keys/rotate")) {
        return next.run(Request::from_parts(parts, Body::empty())).await;
    }
    if parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| {
            value.split(';').next().unwrap_or_default().trim() != "application/json"
        })
    {
        return ApiError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/json".into(),
        )
        .into_response();
    }
    let value = match object(
        &bytes,
        &fields,
        path.ends_with("/restore") && !fields.is_empty(),
    ) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let bytes = match serde_json::to_vec(&value) {
        Ok(bytes) => bytes,
        Err(error) => return ApiError::from(Error::Json(error)).into_response(),
    };
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}
fn object(bytes: &[u8], fields: &[Value], nulls: bool) -> Result<Value, ApiError> {
    let trimmed = bytes.trim_ascii();
    if trimmed.len() < 2 || trimmed.first() != Some(&b'{') {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "request body must be a JSON object".into(),
        ));
    }
    let value: Value = serde_json::from_slice(trimmed).map_err(|error| {
        let message = if error.is_eof() {
            "unexpected end of JSON input".into()
        } else {
            error.to_string()
        };
        ApiError(StatusCode::BAD_REQUEST, format!("invalid JSON: {message}"))
    })?;
    if !nulls && let Some(path) = null_field(&value, "") {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            format!("{path} must not be null"),
        ));
    }
    let object = serde_json::from_slice::<OrderedObject>(trimmed)
        .map_err(|error| ApiError(StatusCode::BAD_REQUEST, format!("invalid JSON: {error}")))?;
    let mut normalized = serde_json::Map::new();
    for (key, value) in object.0 {
        let Some(field) = fields
            .iter()
            .filter_map(Value::as_str)
            .find(|field| crate::casefold::equal(field, &key))
        else {
            return Err(ApiError(
                StatusCode::BAD_REQUEST,
                format!("invalid JSON: json: unknown field {key:?}"),
            ));
        };
        normalized.insert(field.to_owned(), value);
    }
    Ok(Value::Object(normalized))
}
struct OrderedObject(Vec<(String, Value)>);
impl<'de> Deserialize<'de> for OrderedObject {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> serde::de::Visitor<'de> for ObjectVisitor {
            type Value = OrderedObject;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<OrderedObject, M::Error> {
                let mut fields = Vec::new();
                while let Some(field) = map.next_entry()? {
                    fields.push(field);
                }
                Ok(OrderedObject(fields))
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}
fn null_field(value: &Value, path: &str) -> Option<String> {
    match value {
        Value::Null => Some(path.into()),
        Value::Object(fields) => fields.iter().find_map(|(name, value)| {
            null_field(
                value,
                &if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}.{name}")
                },
            )
        }),
        Value::Array(values) => values
            .iter()
            .enumerate()
            .find_map(|(index, value)| null_field(value, &format!("{path}[{index}]"))),
        _ => None,
    }
}

pub(super) fn cross_origin(request: &Request) -> bool {
    if matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) {
        return false;
    }
    match request
        .headers()
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
    {
        "same-origin" | "none" => return false,
        "" => {}
        _ => return true,
    }
    let Some(origin) = request
        .headers()
        .get(header::ORIGIN)
        .filter(|value| !value.is_empty())
    else {
        return false;
    };
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let Some(origin) = origin
        .to_str()
        .ok()
        .and_then(|value| value.parse::<axum::http::Uri>().ok())
    else {
        return true;
    };
    origin
        .authority()
        .is_none_or(|authority| authority.as_str() != host)
}
pub(super) async fn authenticate(
    State(state): State<ApiState>,
    request: Request,
    next: Next,
) -> Response {
    let token = request
        .headers()
        .get("X-Scimtest-Instance-Token")
        .map(|value| value.as_bytes())
        .unwrap_or_default();
    let valid_token = !state.token.is_empty()
        && token.len() == state.token.len()
        && token
            .iter()
            .zip(state.token.as_bytes())
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0;
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_owned())
        .unwrap_or_default();
    let allowed = if path == "/api/v1/" {
        vec!["GET".to_owned()]
    } else if path == "/-/activate" {
        vec!["POST".to_owned()]
    } else {
        routes()
            .iter()
            .filter(|route| route["path"] == path)
            .filter_map(|route| route["method"].as_str().map(str::to_owned))
            .collect::<Vec<_>>()
    };
    let environment = request
        .uri()
        .path()
        .strip_prefix("/api/v1/environments/")
        .and_then(|path| path.split('/').next())
        .map(str::to_owned);
    let mutation = if valid_token && mutates_state(request.method(), &path) {
        let store = state.store.clone();
        tokio::task::spawn_blocking(move || store.mutation().map(drop))
            .await
            .map_err(|error| ApiError(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))
            .and_then(|result| result.map_err(ApiError::from))
    } else {
        Ok(())
    };
    let mut response = if !valid_token {
        ApiError(
            if request.uri().path() == "/-/ready" {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::UNAUTHORIZED
            },
            "valid instance token required".into(),
        )
        .into_response()
    } else if !allowed.is_empty()
        && !allowed
            .iter()
            .any(|method| method == request.method().as_str())
    {
        ApiError(StatusCode::METHOD_NOT_ALLOWED, "method not allowed".into()).into_response()
    } else if let Err(error) = mutation {
        error.into_response()
    } else {
        next.run(request).await
    };
    if response.status() == StatusCode::METHOD_NOT_ALLOWED
        && !allowed.is_empty()
        && let Ok(value) = HeaderValue::from_str(&allowed.join(", "))
    {
        response.headers_mut().insert(header::ALLOW, value);
    }
    if response.status() == StatusCode::NOT_FOUND
        && let Some(environment) = environment
    {
        let (parts, body) = response.into_parts();
        let bytes = match axum::body::to_bytes(body, 1 << 20).await {
            Ok(bytes) => bytes,
            Err(_) => {
                return ApiError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Could not read API error".into(),
                )
                .into_response();
            }
        };
        let mut value = serde_json::from_slice::<Value>(&bytes).ok();
        if let Some(value) = &mut value
            && value["error"] == "environment not found"
        {
            let environment =
                percent_encoding::percent_decode_str(&environment).decode_utf8_lossy();
            value["error"] = json!(format!("environment {environment:?} not found"));
            response = Response::from_parts(parts, Body::from(value.to_string()));
        } else {
            response = Response::from_parts(parts, Body::from(bytes));
        }
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
