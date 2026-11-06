use super::*;
use crate::saml::{self, LogoutMessage, LogoutStatus, OutboundMessage};

pub enum SamlLogout {
    Outbound {
        message: Box<OutboundMessage>,
        clear_cookie: bool,
    },
    Complete {
        user: String,
        detail: String,
    },
}
impl Identity {
    pub fn stage_saml_delivery(&self, id: &str, message: OutboundMessage) -> Result<String> {
        self.saml_directory(id)?;
        let mut memory = self.memory()?;
        let now = Utc::now();
        memory
            .saml_deliveries
            .retain(|_, (_, expires, _)| *expires > now);
        if memory.saml_deliveries.len() >= 20 {
            return Err(ProtocolError::new(
                "invalid_request",
                "too many pending SAML browser requests",
            ));
        }
        let ticket = random_secret(32);
        memory.saml_deliveries.insert(
            ticket.clone(),
            (id.into(), now + Duration::minutes(2), message),
        );
        Ok(ticket)
    }
    pub fn saml_delivery(&self, slug: &str, ticket: &str) -> Result<OutboundMessage> {
        let environment = self.0.store.directory_by_slug(slug)?.environment;
        let mut memory = self.memory()?;
        if !environment.settings.supports_saml()
            || !memory
                .saml_deliveries
                .get(ticket)
                .is_some_and(|(id, expires, _)| *id == environment.id && *expires > Utc::now())
        {
            return Err(Error::NotFound("SAML browser request").into());
        }
        memory
            .saml_deliveries
            .remove(ticket)
            .map(|(_, _, message)| message)
            .ok_or_else(|| Error::NotFound("SAML browser request").into())
    }
    fn saml_directory(&self, id: &str) -> Result<Directory> {
        let directory = self.0.store.directory(id)?;
        if !directory.environment.settings.supports_saml() {
            return Err(ProtocolError::new("invalid_request", "SAML is not enabled"));
        }
        Ok(directory)
    }
    pub fn saml_logouts(&self, id: &str) -> Result<Vec<Value>> {
        self.saml_directory(id)?;
        Ok(self
            .memory()?
            .saml_logouts
            .get(id)
            .cloned()
            .unwrap_or_default())
    }
    pub fn start_saml_logout(
        &self,
        id: &str,
        session_id: &str,
        binding: &str,
        base: &str,
    ) -> Result<OutboundMessage> {
        self.expire_sessions();
        let session = self
            .memory()?
            .sessions
            .get(session_id)
            .filter(|session| session.environment == id)
            .cloned()
            .ok_or(Error::NotFound("session"))?;
        self.start_saml_logout_session(id, session, binding, base)
    }
    pub(super) fn start_saml_logout_session(
        &self,
        id: &str,
        session: Session,
        binding: &str,
        base: &str,
    ) -> Result<OutboundMessage> {
        let directory = self.saml_directory(id)?;
        let environment = &directory.environment;
        let binding = saml::parse_binding(binding)?;
        if session.saml_index.is_empty() {
            return Err(ProtocolError::new(
                "invalid_request",
                "session has no SAML sign-in",
            ));
        }
        if environment.settings.saml_slo_url.trim().is_empty() {
            return Err(ProtocolError::new(
                "invalid_request",
                "set the SP's Single Logout URL on the environment before sending a LogoutRequest",
            ));
        }
        let mut memory = self.memory()?;
        memory.end_session(&session.id, "IdP-initiated SAML logout");
        let now = Utc::now();
        let issuer = format!("{base}/saml/{}/metadata", environment.slug);
        let destination = &environment.settings.saml_slo_url;
        let (request_id, xml) = saml::build_logout_request(
            &issuer,
            destination,
            &session.saml_name_id,
            &session.saml_name_id_format,
            &session.saml_index,
            now,
        );
        let key = self.0.store.active_signing_key(id)?;
        let mut message = saml::encode_logout(&key, binding, "SAMLRequest", destination, xml, "")?;
        message.id = request_id.clone();
        let entries = memory.saml_logouts.entry(id.into()).or_default();
        entries.insert(0,json!({"request_id":request_id,"session_id":session.id,"user":session.label,"binding":message.binding_name(),"destination":destination,"sent_at":now.to_rfc3339_opts(chrono::SecondsFormat::Secs,true),"outcome":"pending"}));
        entries.truncate(10);
        memory.protocol_event(
            id,
            "saml",
            "logout",
            "ok",
            &session.label,
            &format!(
                "LogoutRequest {} for session {} sent to {destination} through the browser ({})",
                message.id,
                session.saml_index,
                message.binding_name()
            ),
        );
        if let Err(error) = self.0.diagnostics.saml_logout(
            "IdP-initiated LogoutRequest sent",
            &[("LogoutRequest to SP", &message.xml)],
        ) {
            eprintln!("Record SAML logout: {error}");
        }
        Ok(message)
    }
    pub fn saml_logout(
        &self,
        slug: &str,
        values: &Parameters,
        cookie: &str,
        base: &str,
        raw_query: &str,
        post: bool,
    ) -> Result<SamlLogout> {
        let directory = self.0.store.directory_by_slug(slug)?;
        let environment = &directory.environment;
        if !environment.settings.supports_saml() {
            return Err(ProtocolError {
                status: 404,
                ..ProtocolError::new("not_found", "SAML is not enabled")
            });
        }
        let message = saml::read_logout(values, post)?;
        let signed = message.verify_sender(environment, raw_query)?;
        let endpoint = format!("{base}/saml/{slug}/slo");
        let id = &environment.id;
        let now = Utc::now();
        if message.response {
            message.check(&endpoint, signed, now)?;
            let status = message.status()?;
            let mut memory = self.memory()?;
            let result = memory.saml_logouts.get_mut(id).into_iter().flatten().find(|entry| entry["request_id"] == message.in_response_to && entry["outcome"] == "pending")
                .ok_or_else(|| ProtocolError::new("invalid_request","LogoutResponse InResponseTo does not match a pending LogoutRequest from scimtest"))?;
            let outcome = if status.is_success() { "ok" } else { "failed" };
            let detail = format!("the SP answered {status}");
            result["outcome"] = json!(outcome);
            result["status"] = json!(status.code);
            result["detail"] = json!(detail);
            result["answered_at"] = json!(now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
            let user = result["user"].as_str().unwrap_or_default().to_owned();
            memory.protocol_event(
                id,
                "saml",
                "logout",
                outcome,
                &user,
                &format!(
                    "LogoutResponse to {} via {}: {detail}",
                    message.in_response_to,
                    saml::binding_name(message.binding)
                ),
            );
            if let Err(error) = self
                .0
                .diagnostics
                .saml_logout(&detail, &[("LogoutResponse from SP", &message.xml)])
            {
                eprintln!("Record SAML logout: {error}");
            }
            return Ok(SamlLogout::Complete {
                user,
                detail: format!("The service provider answered {status}."),
            });
        }
        let destination = &environment.settings.saml_slo_url;
        if destination.trim().is_empty() {
            return Err(ProtocolError::new(
                "invalid_request",
                "set the SP's Single Logout URL on the environment before sending LogoutRequests",
            ));
        }
        self.expire_sessions();
        let mut memory = self.memory()?;
        let sessions = memory
            .sessions
            .values()
            .filter(|session| session.environment == *id && !session.saml_index.is_empty())
            .cloned()
            .collect::<Vec<_>>();
        let (targets, status) = match message.check(&endpoint, signed, now) {
            Err(error) => (Vec::new(), LogoutStatus::requester(error.to_string())),
            Ok(()) => match_sessions(&sessions, &message, cookie),
        };
        let clear_cookie = targets.iter().any(|session| session.id == cookie);
        let users = targets
            .iter()
            .map(|session| session.label.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        for session in &targets {
            memory.end_session(&session.id, "SAML logout from the SP");
        }
        let issuer = format!("{base}/saml/{slug}/metadata");
        let xml = saml::build_logout_response(&issuer, destination, &message.id, &status, now);
        let key = self.0.store.active_signing_key(id)?;
        let response = saml::encode_logout(
            &key,
            message.binding,
            "SAMLResponse",
            destination,
            xml,
            &message.relay_state,
        )?;
        let outcome = if status.is_success() { "ok" } else { "failed" };
        memory.protocol_event(
            id,
            "saml",
            "logout",
            outcome,
            &users,
            &format!(
                "LogoutRequest {} from the SP ended {} live session(s); answered {status} via {}",
                message.id,
                targets.len(),
                response.binding_name()
            ),
        );
        if let Err(error) = self.0.diagnostics.saml_logout(
            &status.to_string(),
            &[
                ("LogoutRequest from SP", &message.xml),
                ("LogoutResponse to SP", &response.xml),
            ],
        ) {
            eprintln!("Record SAML logout: {error}");
        }
        Ok(SamlLogout::Outbound {
            message: Box::new(response),
            clear_cookie,
        })
    }
}
fn match_sessions(
    sessions: &[Session],
    request: &LogoutMessage,
    browser: &str,
) -> (Vec<Session>, LogoutStatus) {
    let name_matches = |session: &Session| {
        session.saml_name_id == request.name_id
            && (request.name_id_format.is_empty()
                || request.name_id_format == session.saml_name_id_format)
    };
    let mut matched = Vec::new();
    for session in sessions {
        if !request.session_indexes.is_empty()
            && !request.session_indexes.contains(&session.saml_index)
        {
            continue;
        }
        if name_matches(session) {
            matched.push(session.clone());
            continue;
        }
        if !request.session_indexes.is_empty() {
            return (
                Vec::new(),
                LogoutStatus::unknown(format!(
                    "NameID {:?} does not match the NameID {:?} of session {}",
                    request.name_id, session.saml_name_id, session.saml_index
                )),
            );
        }
    }
    if !matched.is_empty() {
        return (matched, LogoutStatus::success());
    }
    if sessions.iter().any(name_matches) {
        return (
            Vec::new(),
            LogoutStatus::requester(format!(
                "SessionIndex {} matches no live session for NameID {:?}",
                request.session_indexes.join(", "),
                request.name_id
            )),
        );
    }
    if let Some(session) = sessions.iter().find(|session| session.id == browser) {
        return (
            Vec::new(),
            LogoutStatus::unknown(format!(
                "NameID {:?} does not match this browser's session, which has {:?}",
                request.name_id, session.saml_name_id
            )),
        );
    }
    (Vec::new(), LogoutStatus::success())
}
