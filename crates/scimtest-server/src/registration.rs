use crate::{
    application::{parse_instance_key, parse_public_key, valid_application_id, valid_instance_id},
    lock, network,
    server::{State, error},
    store::{ApplicationProfile, REVOKED_INSTANCE},
};
use anyhow::{Result, bail};
use axum::{body::Body, extract::Request, http::StatusCode, response::Response};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures_util::{SinkExt, Stream, StreamExt};
use hyper_util::rt::TokioIo;
use rand::RngCore;
use scimtest_protocol::{Message, application_challenge_payload, instance_challenge_payload};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        self,
        protocol::{CloseFrame, Role, WebSocketConfig, frame::coding::CloseCode},
    },
};

pub(crate) type Socket = WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>;
pub(crate) const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
mod tests;
const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(30);
const REGISTRATION_LIMIT: usize = 64 << 10;

#[derive(Default)]
pub(crate) struct RegistrationPool {
    counts: Mutex<HashMap<String, usize>>,
}
pub(crate) struct RegistrationGuard {
    pool: Arc<RegistrationPool>,
    ip: String,
}

impl RegistrationPool {
    pub fn acquire(self: &Arc<Self>, ip: String) -> Option<RegistrationGuard> {
        let mut counts = lock(&self.counts);
        if counts.get(&ip).copied().unwrap_or(0) >= 8 || counts.values().sum::<usize>() >= 128 {
            return None;
        }
        *counts.entry(ip.clone()).or_default() += 1;
        Some(RegistrationGuard {
            pool: self.clone(),
            ip,
        })
    }
}

impl Drop for RegistrationGuard {
    fn drop(&mut self) {
        let mut counts = lock(&self.pool.counts);
        if let Some(count) = counts.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}

pub(crate) async fn upgrade(
    state: Arc<State>,
    mut request: Request,
    peer: SocketAddr,
    start: Instant,
) -> Response {
    let headers = request.headers().clone();
    let ip = network::client_ip(peer, &headers, state.config.behind_proxy, &state.trusted);
    let Some(slot) = state.registrations.acquire(network::enrollment_ip(&ip)) else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "too many tunnel registrations; try again later",
        );
    };
    if let Some(origin) = headers
        .get("origin")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
    {
        let origin = origin.strip_prefix("https://").unwrap_or(origin);
        let origin = origin.strip_prefix("http://").unwrap_or(origin);
        if !state.public_host(origin) {
            return error(
                StatusCode::FORBIDDEN,
                "websocket: request origin not allowed by Upgrader.CheckOrigin",
            );
        }
    }
    let method = request.method().to_string();
    if method != "GET" {
        let mut response = error(
            StatusCode::METHOD_NOT_ALLOWED,
            "websocket: the client is not using the websocket protocol: request method is not GET",
        );
        response
            .headers_mut()
            .insert("allow", axum::http::HeaderValue::from_static("GET"));
        return response;
    }
    let path = request.uri().path().to_owned();
    let upgraded = hyper::upgrade::on(&mut request);
    let handshake = request.map(|_| ());
    let response = match tungstenite::handshake::server::create_response(&handshake) {
        Ok(response) => response.map(|_| Body::empty()),
        Err(_) => {
            return error(
                StatusCode::BAD_REQUEST,
                "websocket: invalid upgrade request",
            );
        }
    };
    if let Some(deadline) = handshake
        .extensions()
        .get::<Arc<crate::runtime::deadline::WriteDeadline>>()
    {
        deadline.clear();
    }
    let tasks = state.tasks.clone();
    tasks.spawn(async move {
        tokio::select! {
            _ = state.shutdown.cancelled() => {}
            upgraded = upgraded => {
                if let Ok(upgraded) = upgraded {
                    let config = WebSocketConfig::default().max_message_size(Some(REGISTRATION_LIMIT)).max_frame_size(Some(REGISTRATION_LIMIT));
                    let mut socket = WebSocketStream::from_raw_socket(TokioIo::new(upgraded),Role::Server,Some(config)).await;
                    connection(state.clone(),&mut socket,slot,&ip).await;
                }
            }
        }
        state.request_finished(&method,&path,peer,0,start);
    });
    response
}

async fn connection(state: Arc<State>, socket: &mut Socket, slot: RegistrationGuard, ip: &str) {
    let registered = tokio::select! {
        _ = state.shutdown.cancelled() => return,
        result = tokio::time::timeout(REGISTRATION_TIMEOUT, async {
            let registration = read(socket).await.map_err(|error|read_error(error,1002))?;
            if registration.kind != "register_tunnel" { return Err((1002,"expected register_tunnel".into())); }
            let Some((profile,instance_id)) = authenticate(&state,socket,&registration,ip).await.map_err(|error|read_error(error,1008))? else { return Ok(None); };
            drop(slot);
            let gate = state.profile_gate.clone().read_owned().await;
            let Some(current) = state.store.profile(&profile.id).map_err(|error|(1011,error.to_string()))? else {
                return Err((1008,"application profile changed during registration".into()));
            };
            if registration.instance_public_key.is_empty() && current.settings.public_key != profile.settings.public_key {
                return Err((1008,"application profile changed during registration".into()));
            }
            let state = state.clone();
            state.tasks.clone().spawn_blocking(move|| {
                let _gate = gate;
                crate::tunnel::register(state,current,instance_id,registration)
            }).await
                .map_err(|error|(1011,error.to_string()))?.map(Some)
        }) => result,
    };
    let mut session = match registered {
        Ok(Ok(Some(session))) => session,
        Ok(Ok(None)) => return,
        Ok(Err((code, message))) => {
            close(socket, code, &message).await;
            return;
        }
        Err(_) => {
            close(socket, 1008, "registration timed out").await;
            return;
        }
    };
    let limit = scimtest_protocol::max_message_bytes(state.config.max_body_bytes) as usize;
    socket.set_config(|config| {
        config.max_message_size = Some(limit);
        config.max_frame_size = Some(limit);
    });
    let mut message = Message {
        kind: "tunnel_registered".into(),
        tunnel_id: session.tunnel.id.clone(),
        public_url: session.tunnel.public_url.clone(),
        client_ip: ip.into(),
        ..Default::default()
    };
    if let Ok(Some(instance)) = state
        .store
        .instance(&session.tunnel.profile_id, &session.tunnel.instance_id)
        && instance.is_enrolled()
    {
        message.github_user_id = instance.github_user_id;
        message.github_login = instance.github_login;
    }
    if send(socket, message).await.is_err() {
        return;
    }
    session.run(socket).await;
}

fn read_error(error: anyhow::Error, fallback: u16) -> (u16, String) {
    if matches!(
        error.downcast_ref::<tungstenite::Error>(),
        Some(tungstenite::Error::Capacity(_))
    ) {
        return (1009, "read limit exceeded".into());
    }
    (fallback, error.to_string())
}

async fn authenticate(
    state: &State,
    socket: &mut Socket,
    registration: &Message,
    ip: &str,
) -> Result<Option<(ApplicationProfile, String)>> {
    if !valid_application_id(&registration.application_profile_id)
        || (!registration.instance_id.is_empty() && !valid_instance_id(&registration.instance_id))
        || (registration.instance_id.is_empty() && registration.instance_public_key.is_empty())
    {
        bail!("invalid application profile or instance id");
    }
    let profile = state
        .store
        .profile(&registration.application_profile_id)?
        .ok_or_else(|| anyhow::anyhow!("invalid application profile"))?;
    if registration.instance_public_key.is_empty() {
        if state
            .store
            .instance(&profile.id, &registration.instance_id)?
            .is_none_or(|instance| instance.is_enrolled())
        {
            bail!(
                "legacy installation is not registered; upgrade scimtest to authorize this installation"
            );
        }
        let (challenge, response) = challenge(socket, false).await?;
        let key = parse_public_key(&profile.settings.public_key)
            .map_err(|_| anyhow::anyhow!("application profile has an invalid public key"))?;
        verify(
            &key.bytes,
            &application_challenge_payload(&profile.id, &registration.instance_id, &challenge),
            &response.signature,
        )
        .map_err(|_| anyhow::anyhow!("invalid application signature"))?;
        return Ok(Some((profile, registration.instance_id.clone())));
    }
    let (key, instance_id) = parse_instance_key(&registration.instance_public_key)?;
    let (challenge, response) = challenge(socket, true).await?;
    verify(
        &key,
        &instance_challenge_payload(
            &profile.id,
            &registration.instance_public_key,
            &registration.instance_id,
            &challenge,
        ),
        &response.signature,
    )
    .map_err(|_| anyhow::anyhow!("invalid instance signature"))?;
    if let Some(instance) = state
        .store
        .instance(&profile.id, &instance_id)?
        .filter(|instance| instance.is_enrolled())
    {
        if instance.public_key != STANDARD.encode(key) {
            bail!("instance id is already enrolled with a different key");
        }
        if instance.revoked {
            bail!(REVOKED_INSTANCE);
        }
        if instance.github_user_id > 0 && !instance.github_login.trim().is_empty() {
            return Ok(Some((profile, instance_id)));
        }
    }
    let binding = crate::enrollment::Binding {
        profile: profile.id.clone(),
        instance: instance_id.clone(),
        key: STANDARD.encode(key),
        legacy: registration.instance_id.clone(),
    };
    if response.enrollment_grant.is_empty() {
        send(socket, state.begin_enrollment(binding, ip)?).await?;
        return Ok(None);
    }
    state.consume_grant(&response.enrollment_grant, binding)?;
    Ok(Some((profile, instance_id)))
}

fn verify(key: &[u8; 32], payload: &[u8], signature: &[u8]) -> Result<()> {
    VerifyingKey::from_bytes(key)?.verify(payload, &Signature::from_slice(signature)?)?;
    Ok(())
}

async fn challenge(socket: &mut Socket, enrollment: bool) -> Result<(String, Message)> {
    let mut random = [0; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut random)?;
    let challenge: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    send(
        socket,
        Message {
            kind: "application_challenge".into(),
            challenge: challenge.clone(),
            enrollment_supported: enrollment,
            ..Default::default()
        },
    )
    .await?;
    let response = read(socket).await?;
    if response.kind != "application_signature" {
        bail!("expected application signature");
    }
    Ok((challenge, response))
}

pub(crate) async fn read<
    S: Stream<Item = Result<tungstenite::Message, tungstenite::Error>> + Unpin,
>(
    socket: &mut S,
) -> Result<Message> {
    loop {
        match socket.next().await {
            Some(Ok(tungstenite::Message::Text(text))) => {
                return Ok(Message::decode(text.as_bytes())?);
            }
            Some(Ok(tungstenite::Message::Binary(bytes))) => return Ok(Message::decode(&bytes)?),
            Some(Ok(tungstenite::Message::Close(_))) | None => bail!("tunnel disconnected"),
            Some(Ok(_)) => {}
            Some(Err(error)) => return Err(error.into()),
        }
    }
}

pub(crate) async fn send(socket: &mut Socket, message: Message) -> Result<()> {
    tokio::time::timeout(
        WRITE_TIMEOUT,
        socket.send(tungstenite::Message::Text(
            serde_json::to_string(&message)?.into(),
        )),
    )
    .await??;
    Ok(())
}

async fn close(socket: &mut Socket, code: u16, reason: &str) {
    let mut end = reason.len().min(123);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        socket.close(Some(CloseFrame {
            code: CloseCode::from(code),
            reason: reason[..end].into(),
        })),
    )
    .await;
    drop(result);
}
