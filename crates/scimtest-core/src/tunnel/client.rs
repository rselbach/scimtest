use super::{
    Enrollment, InstallationIdentity,
    protocol::{MAX_MESSAGE, Message},
};
use futures_util::{SinkExt, StreamExt};
use std::{collections::VecDeque, fmt, time::Duration};
use tokio::{net::TcpStream, sync::mpsc, task::JoinSet};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::{self, protocol::WebSocketConfig},
};
use tokio_util::sync::CancellationToken;
use url::Url;

mod connect;
mod forward;
mod polling;

pub(super) enum Event {
    Registered(Registration),
    Enrollment(Enrollment),
}
#[derive(Clone)]
pub(super) struct Registration {
    pub tunnel_id: String,
    pub public_url: String,
    pub client_ip: String,
    pub github_user_id: i64,
    pub github_login: String,
}
pub(super) struct Client {
    server: Url,
    profile: String,
    identity: InstallationIdentity,
    local_port: u16,
    http: reqwest::Client,
    local_http: reqwest::Client,
    grant: String,
    events: mpsc::UnboundedSender<Event>,
    cancellation: CancellationToken,
    proxy: connect::ProxyConfig,
}
#[derive(Debug)]
pub(super) struct Failure {
    pub message: String,
    terminal: bool,
}
impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(formatter)
    }
}
impl Failure {
    fn terminal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            terminal: true,
        }
    }
    fn retry(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            terminal: false,
        }
    }
}
impl From<tungstenite::Error> for Failure {
    fn from(error: tungstenite::Error) -> Self {
        Self::retry(error.to_string())
    }
}
type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
enum End {
    Enrollment(Box<Enrollment>),
    Failure(Failure),
}
impl From<Failure> for End {
    fn from(value: Failure) -> Self {
        Self::Failure(value)
    }
}
impl From<tungstenite::Error> for End {
    fn from(value: tungstenite::Error) -> Self {
        Self::Failure(value.into())
    }
}

impl Client {
    pub(super) fn new(
        server: Url,
        profile: String,
        identity: InstallationIdentity,
        local_port: u16,
        events: mpsc::UnboundedSender<Event>,
        cancellation: CancellationToken,
    ) -> Result<Self, Failure> {
        if !["ws", "wss"].contains(&server.scheme())
            || server.host_str().is_none()
            || !server.username().is_empty()
            || server.password().is_some()
            || server.fragment().is_some()
        {
            return Err(Failure::terminal(
                "tunnel server URL must use WS or WSS without credentials or a fragment",
            ));
        }
        if profile.is_empty() || local_port == 0 {
            return Err(Failure::terminal(
                "application profile id and a local port are required",
            ));
        }
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|error| Failure::terminal(error.to_string()))?;
        let local_http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|error| Failure::terminal(error.to_string()))?;
        Ok(Self {
            server,
            profile,
            identity,
            local_port,
            http,
            local_http,
            grant: String::new(),
            events,
            cancellation,
            proxy: connect::ProxyConfig::from_env(),
        })
    }
    pub(super) async fn run(mut self) -> Result<(), Failure> {
        let mut backoff = Duration::ZERO;
        let cancellation = self.cancellation.clone();
        loop {
            let outcome = tokio::select! {
                _=cancellation.cancelled()=>return Ok(()),
                outcome=self.connection()=>outcome,
            };
            let failure = match outcome {
                Ok(()) => return Ok(()),
                Err(End::Enrollment(enrollment)) => {
                    self.grant.clear();
                    self.events
                        .send(Event::Enrollment((*enrollment).clone()))
                        .map_err(|_| Failure::terminal("tunnel observer is unavailable"))?;
                    match self.poll_enrollment(&enrollment).await {
                        Ok(()) => {
                            backoff = Duration::ZERO;
                            continue;
                        }
                        Err(error) => error,
                    }
                }
                Err(End::Failure(error)) => error,
            };
            if self.cancellation.is_cancelled() {
                return Ok(());
            }
            if failure.terminal {
                return Err(failure);
            }
            backoff = if backoff.is_zero() {
                Duration::from_secs(1)
            } else {
                (backoff * 2).min(Duration::from_secs(30))
            };
            eprintln!(
                "Tunnel connection interrupted; retrying in {}s: {failure}",
                backoff.as_secs()
            );
            tokio::select! { _=self.cancellation.cancelled()=>return Ok(()), _=tokio::time::sleep(backoff)=>{} }
        }
    }
    async fn connection(&mut self) -> Result<(), End> {
        let mut socket = connect::socket(&self.server, &self.proxy).await?;
        send(
            &mut socket,
            Message {
                kind: "register_tunnel".into(),
                local_port: self.local_port.into(),
                application_profile_id: self.profile.clone(),
                instance_id: self.identity.instance_id.clone(),
                instance_public_key: self.identity.public_key(),
                ..Default::default()
            },
        )
        .await?;
        let challenge = read(&mut socket).await?;
        if challenge.kind != "application_challenge" {
            return Err(Failure::terminal(format!(
                "expected application_challenge, got {:?}",
                challenge.kind
            ))
            .into());
        }
        if !challenge.enrollment_supported {
            return Err(Failure::terminal("application private key is required").into());
        }
        let signature = self
            .identity
            .sign_challenge(&self.profile, &challenge.challenge);
        send(
            &mut socket,
            Message {
                kind: "application_signature".into(),
                signature,
                enrollment_grant: self.grant.clone(),
                ..Default::default()
            },
        )
        .await?;
        let mut pending = VecDeque::new();
        let mut pending_bytes = 0;
        let registration = loop {
            let message = read(&mut socket).await?;
            if message.kind != "request" {
                break message;
            }
            let size = serde_json::to_vec(&message)
                .map_err(|error| Failure::terminal(error.to_string()))?
                .len();
            if pending.len() >= 32 || size > MAX_MESSAGE - pending_bytes {
                return Err(
                    Failure::terminal("tunnel registration pending traffic exceeds limit").into(),
                );
            }
            pending_bytes += size;
            pending.push_back(message);
        };
        if registration.kind == "enrollment_required" {
            let enrollment = Enrollment::parse(&self.server, registration).map_err(|error| {
                Failure::terminal(format!("invalid enrollment request: {error}"))
            })?;
            return Err(End::Enrollment(Box::new(enrollment)));
        }
        if registration.kind != "tunnel_registered" {
            return Err(Failure::terminal(format!(
                "expected tunnel_registered, got {:?}",
                registration.kind
            ))
            .into());
        }
        self.grant.clear();
        self.events
            .send(Event::Registered(Registration {
                tunnel_id: registration.tunnel_id,
                public_url: registration.public_url,
                client_ip: registration.client_ip,
                github_user_id: registration.github_user_id,
                github_login: registration.github_login,
            }))
            .map_err(|_| Failure::terminal("tunnel observer is unavailable"))?;
        let mut requests = JoinSet::new();
        loop {
            tokio::select! {
                message=async {
                    match pending.pop_front() {
                        Some(message)=>Ok(message),
                        None=>read(&mut socket).await,
                    }
                }=> {
                    let message=message?;
                    match message.kind.as_str() {
                        "ping"=>send(&mut socket,Message { kind:"pong".into(),..Default::default() }).await?,
                        "request" if requests.len()>=32=>send(&mut socket,Message { kind:"response".into(),stream_id:message.stream_id,error:"local application is busy".into(),..Default::default() }).await?,
                        "request"=> {
                            let client=self.local_http.clone();let port=self.local_port;
                            requests.spawn(async move { forward::request(client,port,message).await });
                        }
                        _=>{}
                    }
                }
                response=requests.join_next(), if !requests.is_empty()=> {
                    match response {
                        Some(Ok(response))=>send(&mut socket,response).await?,
                        Some(Err(error))=>return Err(Failure::retry(format!("forward tunnel request: {error}")).into()),
                        None=>{}
                    }
                }
            }
        }
    }
}
async fn send(socket: &mut Socket, message: Message) -> Result<(), Failure> {
    let json =
        serde_json::to_string(&message).map_err(|error| Failure::terminal(error.to_string()))?;
    tokio::time::timeout(
        Duration::from_secs(10),
        socket.send(tungstenite::Message::Text(json.into())),
    )
    .await
    .map_err(|_| Failure::retry("tunnel write timed out"))??;
    Ok(())
}
async fn read(socket: &mut Socket) -> Result<Message, Failure> {
    loop {
        match socket.next().await {
            Some(Ok(tungstenite::Message::Text(text))) => {
                return Message::decode(text.as_bytes())
                    .map_err(|error| Failure::retry(format!("decode tunnel message: {error}")));
            }
            Some(Ok(tungstenite::Message::Binary(bytes))) => {
                return Message::decode(&bytes)
                    .map_err(|error| Failure::retry(format!("decode tunnel message: {error}")));
            }
            Some(Ok(tungstenite::Message::Close(Some(frame)))) => {
                return Err(Failure {
                    message: format!("tunnel closed: {} {}", frame.code, frame.reason),
                    terminal: frame.code == tungstenite::protocol::frame::coding::CloseCode::Policy,
                });
            }
            Some(Ok(tungstenite::Message::Close(None))) | None => {
                return Err(Failure::retry("tunnel connection closed"));
            }
            Some(Ok(_)) => {}
            Some(Err(error)) => return Err(error.into()),
        }
    }
}
