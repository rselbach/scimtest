use super::authorize::{redirect_url, set_query, validate_redirect};
use super::*;
use tokio::sync::mpsc;

pub enum Logout {
    Confirm {
        user: String,
    },
    Complete {
        redirect: Option<String>,
        clear_cookie: bool,
    },
}

impl Identity {
    pub(super) fn start_sessions(&self, mut ended: mpsc::UnboundedReceiver<Session>) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let weak = Arc::downgrade(&self.0);
        let mut revisions = self.0.store.subscribe();
        handle.spawn(async move {
            let mut timer = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tokio::select! {
                    session = ended.recv() => {
                        let Some(session) = session else { break; };
                        let Some(inner) = weak.upgrade() else { break; };
                        Identity(inner).send_logout(session).await;
                    }
                    changed = revisions.changed() => {
                        if changed.is_err() { break; }
                        let Some(inner) = weak.upgrade() else { break; };
                        let result = tokio::task::spawn_blocking(move || Identity(inner).expire_sessions()).await;
                        if let Err(error) = result { eprintln!("Clean up IdP sessions: {error}"); }
                    }
                    _ = timer.tick() => {
                        let Some(inner) = weak.upgrade() else { break; };
                        let result = tokio::task::spawn_blocking(move || Identity(inner).expire_sessions()).await;
                        if let Err(error) = result { eprintln!("Expire IdP sessions: {error}"); }
                    }
                }
            }
        });
    }
    pub(super) fn expire_sessions(&self) {
        let result = (|| -> Result<()> {
            let directories = self.0.store.snapshot()?;
            let mut memory = self.memory()?;
            memory.prune(Utc::now());
            let invalid = memory
                .sessions
                .values()
                .filter(|session| {
                    !directories.iter().any(|directory| {
                        directory.environment.id == session.environment
                            && active_user(directory, &session.user).is_some()
                    })
                })
                .map(|session| session.id.clone())
                .collect::<Vec<_>>();
            for id in invalid {
                memory.end_session(&id, "user is inactive or missing");
            }
            Ok(())
        })();
        if let Err(error) = result {
            eprintln!("Clean up IdP sessions: {}", error.description);
        }
    }
    pub fn sessions(&self, id: &str) -> Result<Vec<Value>> {
        self.expire_sessions();
        let memory = self.memory()?;
        let mut sessions = memory
            .sessions
            .values()
            .filter(|session| session.environment == id)
            .collect::<Vec<_>>();
        sessions.sort_by_key(|session| std::cmp::Reverse(session.authn.time));
        Ok(sessions.into_iter().map(|session| {
            let mut value = json!({"session_id":session.id,"user_id":session.user,"user":session.label,
                "signed_in_at":session.authn.time.to_rfc3339_opts(chrono::SecondsFormat::Secs,true),
                "authn_strength":session.authn.strength,"protocols":session.protocols,"started_at":session.started.to_rfc3339_opts(chrono::SecondsFormat::Secs,true)});
            if !session.saml_index.is_empty() { value["saml_session_index"] = json!(session.saml_index); }
            if !session.saml_name_id.is_empty() { value["saml_name_id"] = json!(session.saml_name_id); }
            value
        }).collect())
    }
    pub fn end_sessions(&self, id: &str, session: &str) -> Result<usize> {
        self.expire_sessions();
        let mut memory = self.memory()?;
        let ids = memory
            .sessions
            .values()
            .filter(|value| value.environment == id && (session.is_empty() || session == value.id))
            .map(|session| session.id.clone())
            .collect::<Vec<_>>();
        if !session.is_empty() && ids.is_empty() {
            return Err(Error::NotFound("session").into());
        }
        for id in &ids {
            memory.end_session(id, "ended through the API");
        }
        Ok(ids.len())
    }
    pub fn token_holders(&self, id: &str) -> Result<Vec<Value>> {
        let directory = self.0.store.directory(id)?;
        let mut memory = self.memory()?;
        memory.prune(Utc::now());
        let mut holders = Vec::new();
        for user in &directory.users {
            let access = memory
                .access
                .values()
                .filter(|token| token.grant.environment == id && token.grant.user == user.id)
                .count();
            let refresh = memory
                .refresh
                .values()
                .filter(|token| token.grant.environment == id && token.grant.user == user.id)
                .count();
            if access + refresh > 0 {
                holders.push(json!({"user_id":user.id,"user":label(user),"access_tokens":access,"refresh_tokens":refresh}));
            }
        }
        holders.sort_by(|a, b| a["user"].as_str().cmp(&b["user"].as_str()));
        Ok(holders)
    }
    pub fn revoke_tokens(&self, id: &str, user: &str) -> Result<usize> {
        let directory = self.0.store.directory(id)?;
        if !user.is_empty() && !directory.users.iter().any(|value| value.id == user) {
            return Err(Error::NotFound("user").into());
        }
        let mut memory = self.memory()?;
        memory.prune(Utc::now());
        let before = memory.access.len() + memory.refresh.len();
        memory.access.retain(|_, token| {
            token.grant.environment != id || !user.is_empty() && token.grant.user != user
        });
        memory.refresh.retain(|_, token| {
            token.grant.environment != id || !user.is_empty() && token.grant.user != user
        });
        Ok(before - memory.access.len() - memory.refresh.len())
    }
    pub fn logout(
        &self,
        slug: &str,
        values: &Parameters,
        cookie: &str,
        issuer: &str,
        local: bool,
        post: bool,
    ) -> Result<Logout> {
        let directory = self.directory(slug)?;
        let id = &directory.environment.id;
        let client = &directory.environment.settings.oidc_client_id;
        if !param(values, "client_id").is_empty() && param(values, "client_id") != client {
            return Err(ProtocolError::new(
                "invalid_request",
                "client_id is invalid",
            ));
        }
        let hint = param(values, "id_token_hint");
        let mut subject = String::new();
        let mut hinted_session = String::new();
        if !hint.is_empty() {
            let header = hint
                .split('.')
                .next()
                .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
                .and_then(|value| serde_json::from_slice::<Value>(&value).ok())
                .unwrap_or(Value::Null);
            if header["alg"] != "RS256" || header["typ"] != "JWT" {
                return Err(ProtocolError::new(
                    "invalid_request",
                    "id_token_hint must be an RS256 ID token",
                ));
            }
            let keys = self.0.store.published_signing_keys(id, Utc::now())?;
            let claims = keys
                .iter()
                .find(|key| header["kid"] == key.stored.kid)
                .and_then(|key| key.verify_jwt(hint).ok())
                .ok_or_else(|| {
                    ProtocolError::new("invalid_request", "id_token_hint signature is invalid")
                })?;
            let audience = claims["aud"] == *client
                || claims["aud"]
                    .as_array()
                    .is_some_and(|values| values.iter().any(|value| value == client));
            if claims["iss"] != issuer || !audience {
                return Err(ProtocolError::new(
                    "invalid_request",
                    "id_token_hint issuer or audience is invalid",
                ));
            }
            subject = claims["sub"].as_str().unwrap_or_default().into();
            hinted_session = claims["sid"].as_str().unwrap_or_default().into();
        }
        let redirect = param(values, "post_logout_redirect_uri");
        let mut redirect = if redirect.is_empty() {
            None
        } else {
            if hint.is_empty() && param(values, "client_id").is_empty() {
                return Err(ProtocolError::new(
                    "invalid_request",
                    "post_logout_redirect_uri requires id_token_hint or client_id",
                ));
            }
            validate_redirect(&directory, redirect, local, "")?;
            Some(redirect_url(redirect)?)
        };
        self.expire_sessions();
        let mut memory = self.memory()?;
        let browser = memory
            .sessions
            .get(cookie)
            .filter(|session| session.environment == *id)
            .cloned();
        let target = if hinted_session.is_empty() {
            browser.clone()
        } else {
            memory
                .sessions
                .get(&hinted_session)
                .filter(|session| session.environment == *id)
                .cloned()
        };
        let own = !hint.is_empty()
            && browser
                .as_ref()
                .zip(target.as_ref())
                .is_some_and(|(browser, target)| {
                    browser.id == target.id
                        && (!hinted_session.is_empty() || subject == browser.user)
                });
        if let Some(session) = &target
            && !own
            && !(post && param(values, "confirm") == "1")
        {
            return Ok(Logout::Confirm {
                user: session.label.clone(),
            });
        }
        let clear_cookie = browser
            .as_ref()
            .zip(target.as_ref())
            .is_some_and(|(a, b)| a.id == b.id);
        if let Some(session) = &target {
            memory.end_session(&session.id, "RP-initiated logout");
        }
        if let Some(redirect) = &mut redirect
            && !param(values, "state").is_empty()
        {
            set_query(redirect, "state", param(values, "state"));
        }
        Ok(Logout::Complete {
            redirect: redirect.map(Into::into),
            clear_cookie,
        })
    }
}
impl Memory {
    pub(super) fn join_session(
        &mut self,
        environment: &crate::model::Environment,
        user: &User,
        authn: Authn,
        cookie: &str,
        protocol: &str,
        now: DateTime<Utc>,
    ) -> Session {
        let remembered = self
            .sessions
            .get(cookie)
            .filter(|session| session.environment == environment.id)
            .cloned();
        let mut session = match remembered {
            Some(session) if session.user == user.id => session,
            previous => {
                if let Some(previous) = previous {
                    self.end_session(&previous.id, "replaced by another sign-in");
                }
                Session {
                    id: random_secret(24),
                    environment: environment.id.clone(),
                    user: user.id.clone(),
                    label: label(user),
                    authn: authn.clone(),
                    started: now,
                    protocols: Vec::new(),
                    issuer: String::new(),
                    saml_index: String::new(),
                    saml_name_id: String::new(),
                    saml_name_id_format: String::new(),
                }
            }
        };
        session.authn = authn;
        session.label = label(user);
        if !session.protocols.iter().any(|value| value == protocol) {
            session.protocols.push(protocol.into());
        }
        self.sessions.insert(session.id.clone(), session.clone());
        session
    }

    pub(super) fn end_session(&mut self, id: &str, reason: &str) {
        if let Some(session) = self.sessions.remove(id) {
            self.event(&session.environment, "session", &session.label, reason);
            if !session.issuer.is_empty()
                && let Some(sender) = &self.ended
                && let Err(error) = sender.send(session)
            {
                eprintln!("Queue back-channel logout: {error}");
            }
        }
    }
}
