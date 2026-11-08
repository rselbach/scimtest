use super::super::protocol::MAX_BODY;
use super::*;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::collections::BTreeMap;

pub(super) async fn request(client: reqwest::Client, port: u16, message: Message) -> Message {
    let mut response = Message {
        kind: "response".into(),
        stream_id: message.stream_id,
        ..Default::default()
    };
    match forward(client, port, message).await {
        Ok((status, header, body)) => {
            response.status_code = status.into();
            response.header = header;
            response.body = body;
        }
        Err(error) => response.error = error.into(),
    }
    response
}
async fn forward(
    client: reqwest::Client,
    port: u16,
    message: Message,
) -> Result<(u16, BTreeMap<String, Vec<String>>, Vec<u8>), &'static str> {
    let url = local_url(port, &message.path).ok_or("invalid request path")?;
    let method = reqwest::Method::from_bytes(message.method.as_bytes())
        .map_err(|_| "failed to reach local application")?;
    if message.body.len() > MAX_BODY {
        return Err("request body too large");
    }
    let mut headers = HeaderMap::new();
    for (name, values) in message.header {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| "failed to reach local application")?;
        for value in values {
            headers.append(
                name.clone(),
                HeaderValue::from_str(&value).map_err(|_| "failed to reach local application")?,
            );
        }
    }
    remove_hop(&mut headers);
    headers.remove("host");
    headers.remove("content-length");
    let response = client
        .request(method, url)
        .headers(headers)
        .body(message.body)
        .send()
        .await
        .map_err(|_| "failed to reach local application")?;
    let status = response.status().as_u16();
    let mut headers = response.headers().clone();
    remove_hop(&mut headers);
    let body = read_response(response, MAX_BODY).await?;
    let mut serialized = BTreeMap::new();
    for name in headers.keys() {
        let values = headers
            .get_all(name)
            .iter()
            .map(|value| value.to_str().map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "failed to read local response")?;
        let name = name
            .as_str()
            .split('-')
            .map(|part| {
                let mut value = part.to_owned();
                if let Some(first) = value.get_mut(..1) {
                    first.make_ascii_uppercase();
                }
                value
            })
            .collect::<Vec<_>>()
            .join("-");
        serialized.insert(name, values);
    }
    Ok((status, serialized, body))
}
pub(super) async fn read_response(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, &'static str> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "failed to read local response")?
    {
        if body.len() + chunk.len() > limit {
            return Err("local response body too large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
fn local_url(port: u16, path: &str) -> Option<Url> {
    let path = if path.is_empty() { "/" } else { path };
    let decoded = percent_encoding::percent_decode_str(path.split('?').next().unwrap_or_default())
        .decode_utf8()
        .ok()?;
    if !decoded.starts_with('/')
        || decoded.starts_with("//")
        || path.contains('#')
        || path.contains(['\r', '\n', '\0'])
    {
        return None;
    }
    let url = Url::parse(&format!("http://127.0.0.1:{port}{path}")).ok()?;
    (url.host_str() == Some("127.0.0.1") && url.port() == Some(port)).then_some(url)
}
fn remove_hop(headers: &mut HeaderMap) {
    let names = headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|name| name.trim().to_owned())
        .collect::<Vec<_>>();
    for name in names {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}
