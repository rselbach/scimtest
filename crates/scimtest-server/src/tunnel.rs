use crate::{
    application::{RateLimiter, Route},
    lock,
    registration::{Socket, WRITE_TIMEOUT, read},
    server::State,
    store::ApplicationProfile,
};
use futures_util::{SinkExt, Stream, StreamExt};
use rand::seq::SliceRandom;
use scimtest_protocol::Message;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio_tungstenite::tungstenite::{
    self,
    protocol::{CloseFrame, frame::coding::CloseCode},
};
use tokio_util::sync::CancellationToken;

pub(crate) struct Tunnel {
    pub id: String,
    pub public_url: String,
    pub profile_id: String,
    pub instance_id: String,
    pub application_name: String,
    pub local_port: i64,
    pub connected_at: chrono::DateTime<chrono::Utc>,
    pub routes: Vec<Route>,
    pub limiter: Mutex<RateLimiter>,
    pub slots: Arc<Semaphore>,
    pub send: mpsc::Sender<Message>,
    pub pending: Mutex<HashMap<u64, oneshot::Sender<Message>>>,
    pub closed: CancellationToken,
    pub requests: AtomicU64,
}

pub(crate) struct Session {
    pub tunnel: Arc<Tunnel>,
    state: Arc<State>,
    receiver: mpsc::Receiver<Message>,
}

pub(crate) fn register(
    state: Arc<State>,
    profile: ApplicationProfile,
    instance_id: String,
    registration: Message,
) -> Result<Session, (u16, String)> {
    if profile.settings.concurrent_requests <= 0
        || profile.settings.concurrent_requests as u64 > Semaphore::MAX_PERMITS as u64
    {
        return Err((1008, "application limits must be positive".into()));
    }
    let (send, receiver) = mpsc::channel(64);
    let tunnel = {
        let mut tunnels = lock(&state.tunnels);
        if tunnels
            .values()
            .any(|tunnel| tunnel.profile_id == profile.id && tunnel.instance_id == instance_id)
        {
            return Err((
                1008,
                "application instance already has an active tunnel".into(),
            ));
        }
        if tunnels
            .values()
            .filter(|tunnel| tunnel.profile_id == profile.id)
            .count()
            >= state.config.max_tunnels_per_application
        {
            return Err((
                1008,
                format!(
                    "maximum number of tunnels ({}) reached for application {}",
                    state.config.max_tunnels_per_application, profile.settings.name
                ),
            ));
        }
        let remembered = state
            .store
            .tunnel_id(&profile.id, &instance_id)
            .map_err(|error| (1011, error.to_string()))?;
        let reserved_root = state
            .config
            .connect_path
            .trim_start_matches('/')
            .split('/')
            .next()
            .unwrap_or("");
        let id = if !remembered.is_empty()
            && remembered != reserved_root
            && !tunnels.contains_key(&remembered)
        {
            remembered
        } else {
            let mut chosen = None;
            for _ in 0..10 {
                let id = random_id();
                if id != reserved_root
                    && !tunnels.contains_key(&id)
                    && !state
                        .store
                        .tunnel_id_reserved(&id)
                        .map_err(|error| (1011, error.to_string()))?
                {
                    chosen = Some(id);
                    break;
                }
            }
            chosen.ok_or((1008, "could not allocate tunnel id".into()))?
        };
        let tunnel = Arc::new(Tunnel {
            public_url: format!(
                "{}://{}/{id}",
                state.config.public_scheme, state.config.domain
            ),
            id: id.clone(),
            profile_id: profile.id,
            instance_id,
            application_name: profile.settings.name,
            local_port: registration.local_port,
            connected_at: chrono::Utc::now(),
            routes: profile.settings.routes,
            limiter: Mutex::new(RateLimiter::new(
                profile.settings.requests_per_minute,
                profile.settings.request_burst,
            )),
            slots: Arc::new(Semaphore::new(
                profile.settings.concurrent_requests as usize,
            )),
            send,
            pending: Mutex::new(HashMap::new()),
            closed: state.shutdown.child_token(),
            requests: AtomicU64::new(0),
        });
        tunnels.insert(id, tunnel.clone());
        state.tunnels_total.fetch_add(1, Ordering::Relaxed);
        tunnel
    };
    let session = Session {
        tunnel,
        state,
        receiver,
    };
    if session
        .state
        .store
        .remember_tunnel(
            &session.tunnel.profile_id,
            &session.tunnel.instance_id,
            &session.tunnel.id,
            true,
        )
        .is_err()
    {
        return Err((1011, "could not remember application tunnel".into()));
    }
    Ok(session)
}

impl Session {
    pub async fn run(&mut self, socket: &mut Socket) {
        let (mut sink, mut stream) = socket.split();
        let tunnel = self.tunnel.clone();
        let receiver = &mut self.receiver;
        {
            let reader = read_loop(&tunnel, &mut stream);
            let writer = async {
                let mut ping = tokio::time::interval_at(
                    tokio::time::Instant::now() + Duration::from_secs(25),
                    Duration::from_secs(25),
                );
                ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    let message = tokio::select! {
                        _ = tunnel.closed.cancelled() => break,
                        _ = ping.tick() => Message { kind:"ping".into(),..Default::default() },
                        message = receiver.recv() => match message { Some(message)=>message,None=>break },
                    };
                    tokio::time::timeout(
                        WRITE_TIMEOUT,
                        sink.send(tungstenite::Message::Text(
                            serde_json::to_string(&message)?.into(),
                        )),
                    )
                    .await??;
                }
                Ok::<(), anyhow::Error>(())
            };
            tokio::select! { _ = tunnel.closed.cancelled()=>{}, _ = reader=>{}, _ = writer=>{} }
        }
        tunnel.closed.cancel();
        lock(&tunnel.pending).clear();
        let closing = async {
            let sent = sink
                .send(tungstenite::Message::Close(Some(CloseFrame {
                    code: CloseCode::Normal,
                    reason: "bye".into(),
                })))
                .await;
            let flushed = sink.close().await;
            if self.state.config.logs && (sent.is_err() || flushed.is_err()) {
                eprintln!("Tunnel close ended before the peer acknowledged it");
            }
        };
        if tokio::time::timeout(Duration::from_secs(2), closing)
            .await
            .is_err()
            && self.state.config.logs
        {
            eprintln!("Tunnel close timed out");
        }
    }
}

async fn read_loop<S>(tunnel: &Tunnel, stream: &mut S) -> anyhow::Result<()>
where
    S: Stream<Item = Result<tungstenite::Message, tungstenite::Error>> + Unpin,
{
    loop {
        let message = tokio::time::timeout(Duration::from_secs(75), read(stream)).await??;
        if message.kind == "response"
            && let Some(pending) = lock(&tunnel.pending).remove(&message.stream_id)
        {
            // The public request may have ended before its response arrived.
            if pending.send(message).is_err() {
                continue;
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.tunnel.closed.cancel();
        lock(&self.tunnel.pending).clear();
        let mut tunnels = lock(&self.state.tunnels);
        if tunnels
            .get(&self.tunnel.id)
            .is_some_and(|current| Arc::ptr_eq(current, &self.tunnel))
        {
            tunnels.remove(&self.tunnel.id);
        }
    }
}

fn random_id() -> String {
    let adjectives = [
        "airconditioned",
        "blanket",
        "campus",
        "chicken",
        "cosmic",
        "deans",
        "dreamatorium",
        "greendale",
        "human",
        "paintball",
        "pillow",
        "remedial",
        "study",
    ];
    let nouns = [
        "annex",
        "beetle",
        "changnesia",
        "dean",
        "diorama",
        "inspector",
        "meowmeow",
        "pelton",
        "popper",
        "room",
        "timeline",
        "troy",
        "winger",
    ];
    let suffixes = [
        "club",
        "college",
        "committee",
        "fort",
        "group",
        "heist",
        "night",
        "party",
        "quest",
        "semester",
        "table",
        "year",
    ];
    let mut random = rand::thread_rng();
    format!(
        "{}-{}-{}",
        adjectives.choose(&mut random).expect("nonempty words"),
        nouns.choose(&mut random).expect("nonempty words"),
        suffixes.choose(&mut random).expect("nonempty words")
    )
}
