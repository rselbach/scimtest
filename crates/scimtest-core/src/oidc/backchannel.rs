use super::*;

impl Identity {
    pub(super) async fn send_logout(&self, session: Session) {
        let identity = self.clone();
        let copy = session.clone();
        let prepared = tokio::task::spawn_blocking(move || identity.prepare_logout(&copy)).await;
        let (uri, token, faults) = match prepared {
            Ok(Ok(value)) => value,
            result => {
                let detail = match result {
                    Ok(Err(error)) => error.description,
                    Err(error) => error.to_string(),
                    _ => unreachable!(),
                };
                self.logout_result(&session, "", "Logout token", &detail, "skipped");
                return;
            }
        };
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            Ok(client) => client,
            Err(error) => {
                self.logout_result(&session, &uri, "Logout token", &error.to_string(), "failed");
                return;
            }
        };
        let count = if faults.tampers("logout_repeated_jti") {
            2
        } else {
            1
        };
        for attempt in 0..count {
            let tampered = faults
                .tamper
                .iter()
                .any(|fault| fault != "logout_repeated_jti")
                || attempt > 0;
            let description = if tampered {
                "Tampered logout token"
            } else {
                "Logout token"
            };
            let delivered = async {
                let mut response = client
                    .post(&uri)
                    .form(&[("logout_token", &token)])
                    .send()
                    .await?;
                let status = response.status();
                let headers = response.headers().clone();
                let mut body = Vec::new();
                while let Some(chunk) = response.chunk().await? {
                    let remaining = (64usize << 10).saturating_sub(body.len());
                    body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                    if body.len() >= 64 << 10 {
                        break;
                    }
                }
                Ok::<_, reqwest::Error>((status, headers, body))
            }
            .await
            .map_err(reqwest::Error::without_url);
            let recorded = match &delivered {
                Ok((status, headers, body)) => {
                    self.0
                        .diagnostics
                        .backchannel(&uri, &token, Some(*status), headers, body)
                }
                Err(error) => self.0.diagnostics.backchannel(
                    &uri,
                    &token,
                    None,
                    &axum::http::HeaderMap::new(),
                    error.to_string().as_bytes(),
                ),
            };
            if let Err(error) = recorded {
                eprintln!("Record back-channel logout: {error}");
            }
            let (outcome, detail) = match delivered {
                Ok((status, _, _)) if tampered && status.is_success() => (
                    "failed",
                    format!("HTTP {status}; app accepted a tampered logout token"),
                ),
                Ok((status, _, _)) if tampered && status.is_client_error() => (
                    "ok",
                    format!("HTTP {status}; app rejected a tampered logout token"),
                ),
                Ok((status, _, _)) if status.is_success() => ("ok", format!("HTTP {status}")),
                Ok((status, _, _)) => ("failed", format!("HTTP {status}")),
                Err(error) => ("failed", error.to_string()),
            };
            self.logout_result(&session, &uri, description, &detail, outcome);
        }
    }
    fn prepare_logout(&self, session: &Session) -> Result<(String, String, Faults)> {
        let directory = self.0.store.directory(&session.environment)?;
        let settings = &directory.environment.settings;
        if !settings.supports_oidc() || settings.oidc_backchannel_logout_uri.is_empty() {
            return Err(ProtocolError::new(
                "skipped",
                "no back-channel logout URI is set",
            ));
        }
        let faults = self.memory()?.take_faults(&session.environment, true);
        let now = Utc::now();
        let mut claims = json!({"iss":session.issuer,"sub":session.user,"aud":settings.oidc_client_id,
            "iat":now.timestamp(),"exp":(now+Duration::minutes(2)).timestamp(),"jti":random_secret(16),
            "events":{"http://schemas.openid.net/event/backchannel-logout":{}}});
        if settings.oidc_backchannel_logout_session_required {
            claims["sid"] = json!(session.id);
        }
        if faults.tampers("logout_wrong_audience") {
            claims["aud"] = json!(format!("{}-wrong", settings.oidc_client_id));
        }
        if faults.tampers("logout_missing_events") {
            claims.as_object_mut().unwrap().remove("events");
        }
        let signing_faults = Faults {
            tamper: if faults.tampers("logout_alg_none") {
                vec!["alg_none".into()]
            } else {
                Vec::new()
            },
            ..Default::default()
        };
        let key = self.0.store.active_signing_key(&session.environment)?;
        let token = signing_faults.sign(&key, &claims, "logout+jwt")?;
        Ok((settings.oidc_backchannel_logout_uri.clone(), token, faults))
    }
    fn logout_result(
        &self,
        session: &Session,
        uri: &str,
        token: &str,
        response: &str,
        outcome: &str,
    ) {
        let Ok(mut memory) = self.memory() else {
            return;
        };
        let now = Utc::now();
        memory.logout_results.retain(|_, results| {
            results
                .last()
                .and_then(|value| value["At"].as_str())
                .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                .is_some_and(|time| now - time.with_timezone(&Utc) < Duration::hours(24))
        });
        memory
            .logout_results
            .entry(session.id.clone())
            .or_default()
            .push(json!({"Token":token,"URI":uri,"Response":response,"Outcome":outcome,"At":now}));
        memory.event(
            &session.environment,
            "backchannel-logout",
            &session.label,
            response,
        );
        if let Some(event) = memory
            .flows
            .get_mut(&session.environment)
            .and_then(|events| events.first_mut())
        {
            event["Outcome"] = json!(outcome);
        }
    }
    pub fn logout_results(&self, session: &str) -> Result<Vec<Value>> {
        Ok(self
            .memory()?
            .logout_results
            .get(session)
            .cloned()
            .unwrap_or_default())
    }
    pub fn faults(&self, id: &str) -> Result<Faults> {
        Ok(self.memory()?.faults.get(id).cloned().unwrap_or_default())
    }
    pub fn arm_faults(&self, id: &str, faults: Faults) -> Result<()> {
        let faults = faults.normalized()?;
        self.0.store.directory(id)?;
        self.memory()?.faults.insert(id.into(), faults);
        Ok(())
    }
    pub fn disarm_faults(&self, id: &str) -> Result<()> {
        self.memory()?.faults.remove(id);
        Ok(())
    }
}
impl Memory {
    pub(super) fn take_faults(&mut self, id: &str, logout: bool) -> Faults {
        let mut all = self.faults.remove(id).unwrap_or_default();
        let (logout_tamper, sign_in_tamper): (Vec<_>, Vec<_>) = all
            .tamper
            .into_iter()
            .partition(|fault| fault.starts_with("logout_"));
        all.tamper = sign_in_tamper;
        let logout_faults = Faults {
            tamper: logout_tamper,
            ..Default::default()
        };
        let (selected, remaining) = if logout {
            (logout_faults, all)
        } else {
            (all, logout_faults)
        };
        if remaining.active() {
            self.faults.insert(id.into(), remaining);
        }
        selected
    }
}
