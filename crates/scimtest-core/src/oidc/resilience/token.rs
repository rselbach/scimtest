use super::*;

impl Identity {
    pub async fn token_exchange(
        &self,
        slug: String,
        values: Parameters,
        authorization: String,
        issuer: String,
    ) -> Result<Value> {
        let identity = self.clone();
        let prepared = tokio::task::spawn_blocking(move || {
            let reservation = identity.reserve_token_action(&slug, &values, &authorization)?;
            match reservation {
                Some(reservation) => Ok::<_, ProtocolError>(TokenStart::Delay {
                    reservation: Box::new(reservation),
                    slug,
                    values,
                    authorization,
                    issuer,
                }),
                None => identity
                    .token(&slug, &values, &authorization, &issuer)
                    .map(TokenStart::Complete),
            }
        })
        .await
        .map_err(|error| ProtocolError::new("server_error", &error.to_string()))??;
        match prepared {
            TokenStart::Complete(value) => Ok(value),
            TokenStart::Delay {
                reservation,
                slug,
                values,
                authorization,
                issuer,
            } => {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                let identity = self.clone();
                tokio::task::spawn_blocking(move || {
                    identity.token_reserved(
                        &slug,
                        &values,
                        &authorization,
                        &issuer,
                        Some(*reservation),
                    )
                })
                .await
                .map_err(|error| ProtocolError::new("server_error", &error.to_string()))?
            }
        }
    }
    fn reserve_token_action(
        &self,
        slug: &str,
        values: &Parameters,
        authorization: &str,
    ) -> Result<Option<TokenReservation>> {
        let directory = self.directory(slug)?;
        let id = &directory.environment.id;
        let kind = param(values, "grant_type");
        if !["authorization_code", "refresh_token", "client_credentials"].contains(&kind) {
            return Err(ProtocolError::new(
                "unsupported_grant_type",
                "unsupported grant_type",
            ));
        }
        super::super::tokens::authenticate(&directory, values, authorization)?;
        let mut memory = self.memory()?;
        memory.prune(Utc::now());
        let available = memory.resilience.get_mut(id).is_some_and(|run| {
            run.expire(Utc::now());
            run.active() && run.phase == "token" && run.remaining - run.in_flight > 0
        });
        if !available {
            return Ok(None);
        }
        let key = token_key(kind, values);
        if key
            .as_ref()
            .is_some_and(|key| memory.redeeming.contains_key(key))
        {
            return Err(ProtocolError::new(
                "invalid_grant",
                "grant is already being redeemed",
            ));
        }
        match kind {
            "client_credentials" if directory.environment.settings.oidc_public_client => {
                return Err(ProtocolError::new(
                    "unauthorized_client",
                    "client_credentials requires a confidential client",
                ));
            }
            "authorization_code" => {
                let grant = memory
                    .codes
                    .get(param(values, "code"))
                    .filter(|grant| {
                        grant.environment == *id
                            && grant.client == directory.environment.settings.oidc_client_id
                            && grant.redirect == param(values, "redirect_uri")
                    })
                    .ok_or_else(|| {
                        ProtocolError::new(
                            "invalid_grant",
                            "authorization code is invalid or expired",
                        )
                    })?;
                let verifier = param(values, "code_verifier");
                if !grant.challenge.is_empty()
                    && !super::super::tokens::valid_verifier(&grant.challenge, verifier)
                    || grant.challenge.is_empty() && !verifier.is_empty()
                {
                    return Err(ProtocolError::new(
                        "invalid_grant",
                        "PKCE code verifier is invalid",
                    ));
                }
            }
            "refresh_token" => {
                let refresh = memory
                    .refresh
                    .get(param(values, "refresh_token"))
                    .filter(|token| {
                        token.grant.environment == *id
                            && token.grant.client == directory.environment.settings.oidc_client_id
                    })
                    .ok_or_else(|| {
                        ProtocolError::new(
                            "invalid_grant",
                            "refresh token is invalid, expired, or revoked",
                        )
                    })?;
                if param(values, "scope")
                    .split_whitespace()
                    .any(|scope| !has_scope(&refresh.grant.scope, scope))
                {
                    return Err(ProtocolError::new(
                        "invalid_scope",
                        "requested scope was not granted",
                    ));
                }
            }
            _ => {}
        }
        let Some((run, action)) = memory.reserve_resilience(id, "token", Utc::now()) else {
            return Ok(None);
        };
        let phase = format!("token ({kind})");
        if matches!(action, Action::Outage)
            && memory.complete_resilience(id, &run, &phase, Utc::now())
        {
            return Err(ProtocolError {
                status: 503,
                retry_after: Some("5".into()),
                ..ProtocolError::new("temporarily_unavailable", "fault injected by scimtest")
            });
        }
        let owner = random_secret(12);
        if let Some(key) = &key {
            memory.redeeming.insert(key.clone(), owner.clone());
        }
        Ok(Some(TokenReservation {
            identity: self.clone(),
            environment: id.clone(),
            run,
            phase,
            key,
            owner,
            finished: false,
        }))
    }
}
enum TokenStart {
    Complete(Value),
    Delay {
        reservation: Box<TokenReservation>,
        slug: String,
        values: Parameters,
        authorization: String,
        issuer: String,
    },
}
pub(in crate::oidc) struct TokenReservation {
    identity: Identity,
    environment: String,
    run: String,
    phase: String,
    key: Option<String>,
    pub owner: String,
    finished: bool,
}
impl TokenReservation {
    pub(in crate::oidc) fn complete(&mut self, memory: &mut Memory) {
        if memory.complete_resilience(&self.environment, &self.run, &self.phase, Utc::now()) {
            memory.event(&self.environment, "token", "", "Injected delay 3s");
        }
        self.finished = true;
    }
}
impl Drop for TokenReservation {
    fn drop(&mut self) {
        if let Ok(mut memory) = self.identity.memory() {
            if let Some(key) = &self.key
                && memory.redeeming.get(key) == Some(&self.owner)
            {
                memory.redeeming.remove(key);
            }
            if !self.finished
                && let Some(run) = memory
                    .resilience
                    .get_mut(&self.environment)
                    .filter(|run| run.id == self.run && run.in_flight > 0)
            {
                run.in_flight -= 1;
                if run.remaining == run.total && run.in_flight == 0 {
                    run.state = "armed".into();
                }
                run.decision(
                    &self.phase,
                    "canceled",
                    "Request ended before the fault was delivered",
                    Utc::now(),
                );
                memory.resilience_changed();
            }
        }
    }
}
pub(in crate::oidc) fn token_key(kind: &str, values: &Parameters) -> Option<String> {
    let name = match kind {
        "authorization_code" => "code",
        "refresh_token" => "refresh_token",
        _ => return None,
    };
    Some(format!("{kind}:{}", param(values, name)))
}
