use super::*;

pub(super) fn session_steps(
    environment: &Environment,
    user: &str,
    sessions: &[Session],
) -> Vec<LifecycleStep> {
    let settings = &environment.settings;
    let (status, detail) = if !settings.supports_oidc() && !settings.supports_saml() {
        (
            "skipped",
            "The environment has no OIDC or SAML configuration".into(),
        )
    } else if sessions.is_empty() {
        ("skipped", format!("{user} had no live IdP sessions"))
    } else {
        (
            "ok",
            format!(
                "Ended {}",
                sessions
                    .iter()
                    .map(|session| format!(
                        "session {} ({})",
                        session.id,
                        session.protocols.join(", ")
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    };
    let mut steps = vec![LifecycleStep::new(
        "sessions",
        "idp",
        format!("End {user}'s IdP sessions"),
        status,
        detail,
    )];
    let backchannel: Vec<_> = sessions
        .iter()
        .filter(|session| !session.issuer.is_empty())
        .collect();
    let reason = if !settings.supports_oidc() {
        Some("OIDC is not enabled for this environment")
    } else if settings.oidc_backchannel_logout_uri.trim().is_empty() {
        Some("Set the environment's back-channel logout URI to send logout tokens")
    } else if backchannel.is_empty() {
        Some("No ended session had issued ID tokens")
    } else {
        None
    };
    if let Some(reason) = reason {
        steps.push(LifecycleStep::new(
            "backchannel",
            "oidc",
            "Send back-channel logout tokens",
            "skipped",
            reason,
        ));
    } else {
        for session in backchannel {
            let mut step = LifecycleStep::new(
                &format!("backchannel-{}", session.id),
                "oidc",
                format!("Back-channel logout for session {}", session.id),
                "running",
                "Sending a logout token",
            );
            step.session = Some(session.clone());
            steps.push(step);
        }
    }
    let saml: Vec<_> = sessions
        .iter()
        .filter(|session| !session.saml_index.is_empty())
        .collect();
    let reason = if !settings.supports_saml() {
        Some("SAML is not enabled for this environment")
    } else if settings.saml_slo_url.trim().is_empty() {
        Some("Set the SP's Single Logout URL on the environment to send LogoutRequests")
    } else if saml.is_empty() {
        Some("No ended session had signed in over SAML")
    } else {
        None
    };
    if let Some(reason) = reason {
        steps.push(LifecycleStep::new(
            "saml-logout",
            "saml",
            "Send SAML LogoutRequests",
            "skipped",
            reason,
        ));
    } else {
        for session in saml {
            let mut step = LifecycleStep::new(
                &format!("saml-logout-{}", session.id),
                "saml",
                format!("SAML Single Logout for session {}", session.id),
                "needs_browser",
                "A LogoutRequest travels through a browser. Send it from the Lifecycle checklist.",
            );
            step.session = Some(session.clone());
            steps.push(step);
        }
    }
    steps
}
impl Memory {
    pub(super) fn settle_lifecycle(&self, run: &mut LifecycleRun, id: &str) {
        for step in &mut run.steps {
            if step.id.starts_with("backchannel-") {
                let Some(session) = &step.session else {
                    continue;
                };
                let Some(results) = self
                    .logout_results
                    .get(&session.id)
                    .filter(|results| !results.is_empty())
                else {
                    continue;
                };
                step.messages = results
                    .iter()
                    .map(|result| LifecycleMessage {
                        at: result["At"]
                            .as_str()
                            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                            .map(|time| {
                                time.with_timezone(&Utc)
                                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                            })
                            .unwrap_or_default(),
                        sent: result["Token"].as_str().unwrap_or_default().into(),
                        to: result["URI"].as_str().unwrap_or_default().into(),
                        body: String::new(),
                        response: result["Response"].as_str().unwrap_or_default().into(),
                        outcome: result["Outcome"].as_str().unwrap_or_default().into(),
                    })
                    .collect();
                step.status = if step
                    .messages
                    .iter()
                    .any(|message| message.outcome == "failed")
                {
                    "failed"
                } else if step.messages.iter().any(|message| message.outcome == "ok") {
                    "ok"
                } else {
                    "skipped"
                }
                .into();
                step.detail = step
                    .messages
                    .last()
                    .map(|message| message.response.clone())
                    .unwrap_or_default();
            }
            if !step.request_id.is_empty()
                && let Some(result) = self
                    .saml_logouts
                    .get(id)
                    .into_iter()
                    .flatten()
                    .find(|result| result["request_id"] == step.request_id)
            {
                let outcome = result["outcome"].as_str().unwrap_or_default();
                if outcome == "pending" {
                    step.status = "waiting".into();
                    step.detail = "Waiting for the SP's LogoutResponse".into();
                    continue;
                }
                step.status = if outcome == "ok" { "ok" } else { "failed" }.into();
                let detail = result["detail"].as_str().unwrap_or_default();
                step.detail = format!("The SP's LogoutResponse: {detail}");
                if let Some(message) = step.messages.last_mut() {
                    message.response = format!("LogoutResponse: {detail}");
                    message.outcome = step.status.clone();
                }
            }
        }
        run.settle_status();
    }
}
impl Identity {
    pub fn lifecycle_saml_logout(
        &self,
        id: &str,
        run: &str,
        step_id: &str,
        binding: &str,
        base: &str,
    ) -> Result<crate::saml::OutboundMessage> {
        let session = {
            let memory = self.memory()?;
            let run = memory
                .lifecycle
                .get(id)
                .into_iter()
                .flatten()
                .find(|value| value.id == run)
                .ok_or_else(|| ProtocolError {
                    status: 404,
                    ..ProtocolError::new("not_found", &format!("lifecycle run {run:?} not found"))
                })?;
            run.steps
                .iter()
                .find(|step| step.id == step_id && step.can_send_logout())
                .and_then(|step| step.session.clone())
                .ok_or_else(|| {
                    ProtocolError::new(
                        "invalid_request",
                        &format!("step {step_id:?} has no SAML LogoutRequest to send"),
                    )
                })?
        };
        let message = self.start_saml_logout_session(id, session, binding, base)?;
        self.update_lifecycle_step(id, run, step_id, |step| {
            step.request_id = message.id.clone();
            step.status = "waiting".into();
            step.detail = "Waiting for the SP's LogoutResponse".into();
            step.messages.push(LifecycleMessage {
                at: timestamp(),
                sent: format!("LogoutRequest {} ({})", message.id, message.binding_name()),
                to: message.destination.clone(),
                body: String::new(),
                response: String::new(),
                outcome: "pending".into(),
            });
        })?;
        Ok(message)
    }
}
