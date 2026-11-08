use crate::{
    auth::{self, GitHubUser, OAuthIntent, field},
    lock, network,
    replacement::ReplacementIntent,
    server::{State, error, json_response},
    store::EnrollmentActor,
};
use anyhow::{Result, bail};
use axum::{extract::Request, http::StatusCode, response::Response};
use chrono::{DateTime, Duration, Utc};
use scimtest_protocol::Message;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, net::SocketAddr};

pub(crate) type Hash = [u8; 32];
const CONFIRM_COOKIE: &str = "scimtest_enroll_confirm";
pub(crate) const LIMIT_REACHED: &str =
    "this account has reached scimtest's installation limit for this application";
pub(crate) const EXPIRED: &str = "installation authorization is invalid or expired";

#[derive(Clone)]
pub(crate) struct Pending {
    pub user_code: String,
    pub handoff: Hash,
    pub binding: Binding,
    pub ip: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub approved_at: Option<DateTime<Utc>>,
    pub actor: Option<GitHubUser>,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) struct Binding {
    pub profile: String,
    pub instance: String,
    pub key: String,
    pub legacy: String,
}

#[derive(Default)]
pub(crate) struct EnrollmentState {
    pub pending: HashMap<Hash, Pending>,
    by_user_code: HashMap<String, Hash>,
    by_binding: HashMap<Binding, Hash>,
    handoffs: HashMap<Hash, Hash>,
    pub oauth: HashMap<String, OAuthIntent>,
    pub replacements: HashMap<Hash, ReplacementIntent>,
    approvals: HashMap<String, Vec<DateTime<Utc>>>,
}

impl EnrollmentState {
    pub fn prune(&mut self, now: DateTime<Utc>) {
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, pending)| now >= pending.expires_at)
            .map(|(hash, _)| *hash)
            .collect();
        for hash in expired {
            self.remove(hash);
        }
        self.prune_oauth(now);
        self.replacements
            .retain(|_, intent| now < intent.expires_at);
        self.approvals.retain(|_, times| {
            times.retain(|time| *time > now - Duration::hours(1));
            !times.is_empty()
        });
    }

    pub fn remove(&mut self, hash: Hash) {
        if let Some(pending) = self.pending.remove(&hash) {
            self.by_user_code.remove(&pending.user_code);
            self.by_binding.remove(&pending.binding);
            self.handoffs.remove(&pending.handoff);
        }
        self.replacements
            .retain(|_, intent| intent.enrollment != hash);
    }

    pub fn approve(&mut self, hash: Hash, user: GitHubUser, now: DateTime<Utc>) {
        if let Some(pending) = self.pending.get_mut(&hash) {
            pending.actor = Some(user);
            pending.approved_at = Some(now);
            self.handoffs.remove(&pending.handoff);
            self.approvals
                .entry(pending.ip.clone())
                .or_default()
                .push(now);
        }
        self.replacements
            .retain(|_, intent| intent.enrollment != hash);
    }

    pub fn approved_count(&self, hash: Hash, profile: &str, user: i64) -> usize {
        self.pending
            .iter()
            .filter(|(other, pending)| {
                **other != hash
                    && pending.binding.profile == profile
                    && pending.approved_at.is_some()
                    && pending.actor.as_ref().is_some_and(|actor| actor.id == user)
            })
            .count()
    }
}

impl State {
    pub fn begin_enrollment(&self, binding: Binding, ip: &str) -> Result<Message> {
        if !self.github_configured() {
            bail!(
                "installation authorization is unavailable because GitHub OAuth is not configured"
            );
        }
        let now = Utc::now();
        let ip = network::enrollment_ip(ip);
        let mut state = lock(&self.enrollment);
        state.prune(now);
        if let Some(old) = state.by_binding.get(&binding).copied() {
            state.remove(old);
        }
        let pending_count = state
            .pending
            .values()
            .filter(|pending| pending.ip == ip && pending.approved_at.is_none())
            .count();
        if pending_count + state.approvals.get(&ip).map_or(0, Vec::len) >= 10 {
            bail!("too many new installations from this network; try again later");
        }
        if state.pending.len() >= 1000 {
            bail!("too many pending installation authorizations; try again later");
        }
        let device = unique_hex(32, |value| state.pending.contains_key(&hash(value)))?;
        let user_code = unique_hex(12, |value| state.by_user_code.contains_key(value))?;
        let handoff = unique_hex(32, |value| state.handoffs.contains_key(&hash(value)))?;
        let device_hash = hash(&device);
        let handoff_hash = hash(&handoff);
        state.by_user_code.insert(user_code.clone(), device_hash);
        state.by_binding.insert(binding.clone(), device_hash);
        state.handoffs.insert(handoff_hash, device_hash);
        state.pending.insert(
            device_hash,
            Pending {
                user_code: user_code.clone(),
                handoff: handoff_hash,
                binding,
                ip,
                created_at: now,
                expires_at: now + Duration::minutes(10),
                approved_at: None,
                actor: None,
            },
        );
        Ok(Message {
            kind: "enrollment_required".into(),
            enrollment_url: format!(
                "{}://{}/enroll?code={user_code}",
                self.config.public_scheme, self.config.dashboard_domain
            ),
            enrollment_browser_handoff_url: format!(
                "{}://{}/enroll/browser?handoff={handoff}",
                self.config.public_scheme, self.config.dashboard_domain
            ),
            enrollment_status_url: format!(
                "{}://{}/api/enroll/status",
                self.config.public_scheme, self.config.domain
            ),
            enrollment_device_code: device,
            enrollment_verification_code: user_code,
            enrollment_poll_seconds: 2,
            ..Default::default()
        })
    }

    pub fn enrollment_status(&self, request: &Request) -> Response {
        if request.method() != "POST" {
            return auth::method_not_allowed("POST");
        }
        let mut response = {
            let token = auth::header(request.headers(), "authorization")
                .trim()
                .split_once(' ')
                .filter(|(scheme, token)| {
                    scheme.eq_ignore_ascii_case("bearer") && auth::valid_hex(token, 64)
                })
                .map(|(_, token)| token);
            if let Some(token) = token {
                let mut state = lock(&self.enrollment);
                state.prune(Utc::now());
                match state.pending.get(&hash(token)) {
                    Some(pending) => json_response(
                        json!({"status":if pending.approved_at.is_some() { "approved" } else { "pending" }}),
                    ),
                    None => error(
                        StatusCode::NOT_FOUND,
                        "installation authorization not found",
                    ),
                }
            } else {
                let mut response = error(StatusCode::UNAUTHORIZED, "missing enrollment credential");
                response.headers_mut().insert(
                    "www-authenticate",
                    axum::http::HeaderValue::from_static("Bearer"),
                );
                response
            }
        };
        response.headers_mut().insert(
            "cache-control",
            axum::http::HeaderValue::from_static("no-store"),
        );
        response
    }

    fn enrollment_by_code(&self, code: &str) -> Option<(Hash, Pending)> {
        if !auth::valid_hex(code, 24) {
            return None;
        }
        let mut state = lock(&self.enrollment);
        state.prune(Utc::now());
        let hash = *state.by_user_code.get(code)?;
        state
            .pending
            .get(&hash)
            .cloned()
            .map(|pending| (hash, pending))
    }

    pub async fn enrollment_page(&self, request: Request, peer: SocketAddr) -> Response {
        if request.method() == "GET" {
            let query = auth::query(&request);
            let code = field(&query, "code");
            let Some((_, pending)) = self.enrollment_by_code(code) else {
                return error(StatusCode::GONE, EXPIRED);
            };
            let profile = match self.store.profile(&pending.binding.profile) {
                Ok(Some(profile)) => profile,
                _ => return error(StatusCode::NOT_FOUND, "application profile not found"),
            };
            let csrf = match auth::random_hex(24) {
                Ok(csrf) => csrf,
                Err(_) => {
                    return error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "could not create confirmation",
                    );
                }
            };
            let mut response = self.page("enrollment.html", json!({"UserCode":code,"CSRFToken":csrf,"ApplicationName":profile.settings.name,"InstanceFingerprint":pending.binding.instance,"ShowVerificationCode":field(&query,"presentation") != "desktop"}));
            self.set_cookie(&mut response, CONFIRM_COOKIE, &csrf, "Strict; Max-Age=600");
            return response;
        }
        if request.method() != "POST" {
            return auth::method_not_allowed("GET, POST");
        }
        if !self.allowed_mutation(&request) {
            return error(StatusCode::FORBIDDEN, "invalid confirmation origin");
        }
        let cookie = auth::cookie(request.headers(), &self.cookie_name(CONFIRM_COOKIE))
            .unwrap_or("")
            .to_owned();
        let (parts, body) = request.into_parts();
        let values = match auth::form(Request::from_parts(parts.clone(), body), 4 << 10).await {
            Ok(values) => values,
            Err(_) => return error(StatusCode::BAD_REQUEST, "invalid confirmation"),
        };
        if !auth::equal_secret(&cookie, field(&values, "csrf_token")) {
            return error(StatusCode::BAD_REQUEST, "invalid confirmation");
        }
        let mut response = if let Some((hash, _)) = self.enrollment_by_code(field(&values, "code"))
        {
            self.begin_oauth(
                &Request::from_parts(parts, axum::body::Body::empty()),
                peer,
                Some(hash),
            )
            .unwrap_or_else(|_| {
                error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not create login state",
                )
            })
        } else {
            error(StatusCode::GONE, EXPIRED)
        };
        self.clear_cookie(&mut response, CONFIRM_COOKIE);
        response
    }

    pub fn enrollment_handoff(&self, request: &Request, peer: SocketAddr) -> Response {
        let mut response = self.start_enrollment_handoff(request, peer);
        response.headers_mut().insert(
            "cache-control",
            axum::http::HeaderValue::from_static("no-store"),
        );
        response.headers_mut().insert(
            "referrer-policy",
            axum::http::HeaderValue::from_static("no-referrer"),
        );
        response
    }

    fn start_enrollment_handoff(&self, request: &Request, peer: SocketAddr) -> Response {
        if request.method() != "GET" {
            return auth::method_not_allowed("GET");
        }
        let query = auth::query(request);
        let handoff = field(&query, "handoff");
        if !auth::valid_hex(handoff, 64) {
            return error(StatusCode::GONE, EXPIRED);
        }
        let handoff_hash = hash(handoff);
        let device = {
            let mut state = lock(&self.enrollment);
            state.prune(Utc::now());
            state.handoffs.remove(&handoff_hash).filter(|hash| {
                state
                    .pending
                    .get(hash)
                    .is_some_and(|pending| pending.approved_at.is_none())
            })
        };
        let Some(device) = device else {
            return error(StatusCode::GONE, EXPIRED);
        };
        let response = self
            .begin_oauth(request, peer, Some(device))
            .unwrap_or_else(|_| {
                error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not create login state",
                )
            });
        if response.status() != StatusCode::FOUND {
            let mut state = lock(&self.enrollment);
            state.prune(Utc::now());
            if state.pending.get(&device).is_some_and(|pending| {
                pending.approved_at.is_none() && pending.handoff == handoff_hash
            }) {
                state.handoffs.entry(handoff_hash).or_insert(device);
            }
        }
        response
    }

    pub fn approve_or_replace(&self, device: Hash, user: GitHubUser) -> Response {
        let result = (|| -> Result<()> {
            let mut state = lock(&self.enrollment);
            state.prune(Utc::now());
            let pending = state
                .pending
                .get(&device)
                .ok_or_else(|| anyhow::anyhow!(EXPIRED))?;
            if pending.approved_at.is_some() {
                bail!("installation authorization was already used");
            }
            self.prune_idle(&pending.binding.profile)?;
            let count = self
                .store
                .count_instances_for_user(&pending.binding.profile, user.id)?
                + state.approved_count(device, &pending.binding.profile, user.id);
            if count >= self.config.max_installations_per_user {
                bail!(LIMIT_REACHED);
            }
            state.approve(device, user.clone(), Utc::now());
            Ok(())
        })();
        match result {
            Ok(()) => self.page("complete.html", json!({})),
            Err(error) if error.to_string() == LIMIT_REACHED => self
                .replacement_page(device, user, "")
                .unwrap_or_else(|error| {
                    crate::server::error(StatusCode::FORBIDDEN, &error.to_string())
                }),
            Err(error) => crate::server::error(StatusCode::FORBIDDEN, &error.to_string()),
        }
    }

    pub fn consume_grant(&self, grant: &str, binding: Binding) -> Result<()> {
        if !auth::valid_hex(grant, 64) {
            bail!("invalid or unapproved installation grant");
        }
        let device = hash(grant);
        let mut state = lock(&self.enrollment);
        state.prune(Utc::now());
        let pending = state
            .pending
            .get(&device)
            .filter(|pending| pending.approved_at.is_some())
            .ok_or_else(|| anyhow::anyhow!("invalid or unapproved installation grant"))?;
        if pending.binding != binding {
            bail!("installation grant does not match this installation");
        }
        let actor = pending
            .actor
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("github enrollment identity is required"))?;
        self.store.enroll_instance(
            &binding.profile,
            &binding.instance,
            &binding.key,
            EnrollmentActor {
                github_user_id: actor.id,
                github_login: actor.login.clone(),
            },
        )?;
        state.remove(device);
        Ok(())
    }

    pub fn prune_idle(&self, profile: &str) -> Result<()> {
        let active = lock(&self.tunnels)
            .values()
            .filter(|tunnel| tunnel.profile_id == profile)
            .map(|tunnel| tunnel.instance_id.clone())
            .collect();
        self.store.prune_idle_instances(
            profile,
            Utc::now() - Duration::days(crate::application::INSTANCE_MAX_IDLE_DAYS),
            &active,
        )?;
        Ok(())
    }
}

pub(crate) fn hash(value: &str) -> Hash {
    Sha256::digest(value.as_bytes()).into()
}

pub(crate) fn unique_hex(bytes: usize, exists: impl Fn(&str) -> bool) -> Result<String> {
    for _ in 0..10 {
        let value = auth::random_hex(bytes)?;
        if !exists(&value) {
            return Ok(value);
        }
    }
    bail!("could not create installation authorization")
}
