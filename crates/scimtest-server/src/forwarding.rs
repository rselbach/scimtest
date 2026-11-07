use crate::{
    application::request_allowed,
    lock, network,
    server::{State, error, not_found},
    tunnel::Tunnel,
};
use axum::{
    body::{Body, Bytes, to_bytes},
    extract::Request,
    http::{HeaderName, HeaderValue, StatusCode},
    response::Response,
};
use futures_util::stream;
use scimtest_protocol::Message;
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::sync::oneshot;

struct Pending {
    tunnel: Arc<Tunnel>,
    id: u64,
}
impl Drop for Pending {
    fn drop(&mut self) {
        lock(&self.tunnel.pending).remove(&self.id);
    }
}

pub(crate) async fn forward(
    state: Arc<State>,
    tunnel: Arc<Tunnel>,
    request: Request,
    peer: SocketAddr,
    host: &str,
) -> Response {
    if !request_allowed(
        &tunnel.routes,
        &format!("/{}", tunnel.id),
        request.method().as_str(),
        request.uri().path(),
    ) {
        return not_found();
    }
    if !lock(&tunnel.limiter).allow() {
        return error(StatusCode::TOO_MANY_REQUESTS, "tunnel rate limit exceeded");
    }
    let Ok(permit) = tunnel.slots.clone().try_acquire_owned() else {
        return error(StatusCode::TOO_MANY_REQUESTS, "tunnel busy");
    };
    tunnel.requests.fetch_add(1, Ordering::Relaxed);
    let (parts, body) = request.into_parts();
    let body = match tokio::time::timeout(
        Duration::from_secs(30),
        to_bytes(body, state.config.max_body_bytes as usize),
    )
    .await
    {
        Ok(Ok(body)) => body,
        _ => return error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"),
    };
    let stream_id = state
        .next_stream
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1);
    let (send, receive) = oneshot::channel();
    lock(&tunnel.pending).insert(stream_id, send);
    let _pending = Pending {
        tunnel: tunnel.clone(),
        id: stream_id,
    };
    let ip = network::client_ip(
        peer,
        &parts.headers,
        state.config.behind_proxy,
        &state.trusted,
    );
    let scheme = network::scheme(
        peer,
        &parts.headers,
        state.config.behind_proxy,
        &state.trusted,
    );
    let mut headers = parts.headers;
    network::remove_hop_headers(&mut headers);
    for (name, value) in [
        ("x-forwarded-for", ip.as_str()),
        ("x-forwarded-host", host),
        ("x-forwarded-proto", scheme.as_str()),
    ] {
        headers.remove(name);
        if let Ok(value) = HeaderValue::from_str(value) {
            headers.insert(HeaderName::from_static(name), value);
        }
    }
    let message = Message {
        kind: "request".into(),
        stream_id,
        method: parts.method.to_string(),
        path: parts
            .uri
            .path_and_query()
            .map_or("/", |value| value.as_str())
            .into(),
        host: host.into(),
        scheme,
        header: network::wire_headers(&headers),
        body: body.to_vec(),
        ..Default::default()
    };
    tokio::select! {
        _ = tunnel.closed.cancelled() => return error(StatusCode::BAD_GATEWAY,"tunnel disconnected"),
        result = tunnel.send.send(message) => if result.is_err() { return error(StatusCode::BAD_GATEWAY,"tunnel disconnected"); },
    }
    let message = tokio::select! {
        _ = tunnel.closed.cancelled() => return error(StatusCode::BAD_GATEWAY,"tunnel disconnected"),
        response = tokio::time::timeout(Duration::from_secs(120),receive) => match response {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => return error(StatusCode::BAD_GATEWAY,"tunnel disconnected"),
            Err(_) => return error(StatusCode::GATEWAY_TIMEOUT,"tunnel response timed out"),
        }
    };
    if !message.error.is_empty() {
        return error(StatusCode::BAD_GATEWAY, &message.error);
    }
    let bytes = Bytes::from(message.body);
    // Keep the concurrency slot until the response drains or the client disconnects.
    let body = Body::from_stream(stream::unfold(
        (bytes, permit),
        |(mut bytes, permit)| async move {
            if bytes.is_empty() {
                return None;
            }
            let chunk = bytes.split_to(bytes.len().min(16 << 10));
            Some((Ok::<_, Infallible>(chunk), (bytes, permit)))
        },
    ));
    let mut response = Response::new(body);
    let status = if message.status_code == 0 {
        200
    } else {
        message.status_code
    };
    *response.status_mut() = u16::try_from(status)
        .ok()
        .and_then(|status| StatusCode::from_u16(status).ok())
        .unwrap_or(StatusCode::BAD_GATEWAY);
    for (name, values) in message.header {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        for value in values {
            if let Ok(value) = HeaderValue::from_str(&value) {
                response.headers_mut().append(name.clone(), value);
            }
        }
    }
    network::remove_hop_headers(response.headers_mut());
    response
}
