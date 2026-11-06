use super::*;
use sha2::{Digest, Sha256};

impl Identity {
    pub fn token(
        &self,
        slug: &str,
        values: &Parameters,
        authorization: &str,
        issuer: &str,
    ) -> Result<Value> {
        self.token_reserved(slug, values, authorization, issuer, None)
    }
    pub(super) fn token_reserved(
        &self,
        slug: &str,
        values: &Parameters,
        authorization: &str,
        issuer: &str,
        mut reservation: Option<super::resilience::TokenReservation>,
    ) -> Result<Value> {
        let directory = self.directory(slug)?;
        let settings = &directory.environment.settings;
        let kind = param(values, "grant_type");
        if !["authorization_code", "refresh_token", "client_credentials"].contains(&kind) {
            return Err(ProtocolError::new(
                "unsupported_grant_type",
                "grant_type must be authorization_code, refresh_token, or client_credentials",
            ));
        }
        authenticate(&directory, values, authorization)?;
        let now = Utc::now();
        let mut memory = self.memory()?;
        if let Some(reservation) = &mut reservation {
            reservation.complete(&mut memory);
        }
        memory.prune(now);
        if let Some(key) = super::resilience::token_key(kind, values)
            && let Some(owner) = memory.redeeming.get(&key)
            && reservation
                .as_ref()
                .is_none_or(|reservation| &reservation.owner != owner)
        {
            return Err(ProtocolError::new(
                "invalid_grant",
                "grant is already being redeemed",
            ));
        }
        if kind == "client_credentials" {
            if settings.oidc_public_client {
                return Err(ProtocolError::new(
                    "unauthorized_client",
                    "client_credentials requires a confidential client",
                ));
            }
            let grant = Grant {
                environment: directory.environment.id.clone(),
                client: settings.oidc_client_id.clone(),
                scope: param(values, "scope").into(),
                ..Default::default()
            };
            let access = self.mint_access(&mut memory, &directory, &grant, issuer, now)?;
            let mut response =
                json!({"access_token":access,"token_type":"Bearer","expires_in":3600});
            if !grant.scope.is_empty() {
                response["scope"] = json!(grant.scope);
            }
            memory.event(
                &grant.environment,
                "token",
                "",
                "Access token issued (client_credentials)",
            );
            return Ok(response);
        }
        let mut original_refresh = None;
        let mut grant = if kind == "authorization_code" {
            let value = param(values, "code");
            let grant = memory.codes.get(value).cloned().ok_or_else(|| {
                ProtocolError::new("invalid_grant", "authorization code is invalid or expired")
            })?;
            if grant.environment != directory.environment.id
                || grant.client != settings.oidc_client_id
                || grant.redirect != param(values, "redirect_uri")
            {
                return Err(ProtocolError::new(
                    "invalid_grant",
                    "authorization code does not match this request",
                ));
            }
            let verifier = param(values, "code_verifier");
            if !grant.challenge.is_empty() && !valid_verifier(&grant.challenge, verifier) {
                return Err(ProtocolError::new(
                    "invalid_grant",
                    "PKCE code verifier is invalid",
                ));
            }
            if grant.challenge.is_empty() && !verifier.is_empty() {
                return Err(ProtocolError::new(
                    "invalid_grant",
                    "code_verifier provided but the authorization request used no code_challenge",
                ));
            }
            memory.codes.remove(value);
            if !grant.faults.token_error.is_empty() {
                return Err(ProtocolError::new(
                    &grant.faults.token_error,
                    "injected token error",
                ));
            }
            Grant {
                grant_id: random_secret(16),
                ..grant
            }
        } else {
            let refresh = memory
                .refresh
                .get(param(values, "refresh_token"))
                .cloned()
                .filter(|refresh| {
                    refresh.grant.environment == directory.environment.id
                        && refresh.grant.client == settings.oidc_client_id
                })
                .ok_or_else(|| {
                    ProtocolError::new(
                        "invalid_grant",
                        "refresh token is invalid, expired, or revoked",
                    )
                })?;
            let mut grant = refresh.grant;
            let requested = param(values, "scope");
            if !requested.is_empty()
                && requested
                    .split_whitespace()
                    .any(|scope| !has_scope(&grant.scope, scope))
            {
                return Err(ProtocolError::new(
                    "invalid_scope",
                    "requested scope was not granted",
                ));
            }
            original_refresh = Some(grant.clone());
            if !requested.is_empty() {
                grant.scope = requested.into();
            }
            grant.nonce.clear();
            grant.faults = Faults::default();
            grant
        };
        let user = match active_user(&directory, &grant.user) {
            Some(user) => user,
            None => {
                if kind == "refresh_token" {
                    memory.refresh.remove(param(values, "refresh_token"));
                }
                return Err(ProtocolError::new(
                    "invalid_grant",
                    "user is inactive or missing",
                ));
            }
        };
        let stage = if original_refresh.is_some() {
            "Tokens refreshed"
        } else {
            "Tokens issued"
        };
        let mut response =
            self.issue_tokens(&mut memory, &directory, user, &grant, issuer, stage, now)?;
        if let Some(original) = original_refresh {
            let replacement = random_secret(32);
            memory.refresh.remove(param(values, "refresh_token"));
            memory.refresh.insert(
                replacement.clone(),
                Refresh {
                    grant: original,
                    issued: now,
                    expires: now + Duration::hours(24),
                },
            );
            response["refresh_token"] = json!(replacement);
        } else if has_scope(&grant.scope, "offline_access") {
            grant.nonce.clear();
            grant.faults = Faults::default();
            let value = random_secret(32);
            memory.refresh.insert(
                value.clone(),
                Refresh {
                    grant: grant.clone(),
                    issued: now,
                    expires: now + Duration::hours(24),
                },
            );
            response["refresh_token"] = json!(value);
        }
        memory.event(&grant.environment, "token", &label(user), stage);
        Ok(response)
    }
    #[allow(clippy::too_many_arguments)]
    fn issue_tokens(
        &self,
        memory: &mut Memory,
        directory: &Directory,
        user: &User,
        grant: &Grant,
        issuer: &str,
        stage: &str,
        now: DateTime<Utc>,
    ) -> Result<Value> {
        let mut claims = claims::user_claims(directory, user, &grant.scope, issuer);
        claims["iss"] = json!(issuer);
        claims["iat"] = json!(now.timestamp());
        claims["aud"] = json!(directory.environment.settings.oidc_client_id);
        grant.authn.add_claims(&mut claims, grant.faults.skew());
        if !grant.nonce.is_empty() {
            claims["nonce"] = json!(grant.nonce);
        }
        if !grant.session.is_empty() {
            claims["sid"] = json!(grant.session);
        }
        grant.faults.apply(&mut claims, now);
        let key = self.0.store.active_signing_key(&directory.environment.id)?;
        let id_token = grant.faults.sign(&key, &claims, "JWT")?;
        memory.note_groups(
            directory,
            &user.id,
            "oidc",
            "ID token",
            &directory.environment.settings.oidc_client_id,
            lifecycle::IssuedGroups::claims(
                &claims,
                &directory.environment.settings.oidc_claim_mappings.groups,
            ),
        );
        let access = self.mint_access(memory, directory, grant, issuer, now)?;
        if let Some(session) = memory.sessions.get_mut(&grant.session) {
            session.issuer = issuer.into();
        }
        memory.inspection(grant, user, stage, &claims, &id_token)?;
        Ok(
            json!({"access_token":access,"token_type":"Bearer","expires_in":3600,"id_token":id_token,"scope":grant.scope}),
        )
    }
    fn mint_access(
        &self,
        memory: &mut Memory,
        directory: &Directory,
        grant: &Grant,
        issuer: &str,
        now: DateTime<Utc>,
    ) -> Result<String> {
        let settings = &directory.environment.settings;
        let mut value = random_secret(32);
        let mut audience = String::new();
        if settings.oidc_jwt_access_tokens {
            audience = if settings.oidc_access_token_audience.is_empty() {
                settings.oidc_client_id.clone()
            } else {
                settings.oidc_access_token_audience.clone()
            };
            let issued = now + grant.faults.skew();
            let mut claims = json!({"iss":issuer,"sub":if grant.user.is_empty() { &grant.client } else { &grant.user },
                "aud":audience,"client_id":settings.oidc_client_id,"scope":grant.scope,
                "iat":issued.timestamp(),"exp":(issued+Duration::hours(1)).timestamp(),"jti":value});
            if !grant.user.is_empty() {
                grant.authn.add_claims(&mut claims, grant.faults.skew());
            }
            grant.faults.tamper_claims(&mut claims);
            let key = self.0.store.active_signing_key(&directory.environment.id)?;
            value = grant.faults.sign(&key, &claims, "at+jwt")?;
        }
        memory.access.insert(
            value.clone(),
            Access {
                grant: grant.clone(),
                issued: now,
                expires: now + Duration::hours(1),
                audience,
            },
        );
        Ok(value)
    }
    pub fn userinfo(&self, slug: &str, authorization: &str, issuer: &str) -> Result<Value> {
        let directory = self.directory(slug)?;
        let mut memory = self.memory()?;
        memory.prune(Utc::now());
        let access = access_for(&memory, &directory, authorization)?;
        let user = active_user(&directory, &access.grant.user).ok_or_else(|| {
            ProtocolError::unauthorized("invalid_token", "user is inactive or missing")
        })?;
        let mut claims = claims::user_claims(&directory, user, &access.grant.scope, issuer);
        access.grant.faults.drop(&mut claims);
        memory.note_groups(
            &directory,
            &user.id,
            "oidc",
            "userinfo response",
            &directory.environment.settings.oidc_client_id,
            lifecycle::IssuedGroups::claims(
                &claims,
                &directory.environment.settings.oidc_claim_mappings.groups,
            ),
        );
        memory.event(
            &directory.environment.id,
            "userinfo",
            &label(user),
            "Userinfo claims served",
        );
        Ok(claims)
    }
    pub fn introspect(
        &self,
        slug: &str,
        values: &Parameters,
        authorization: &str,
        issuer: &str,
    ) -> Result<Value> {
        let directory = self.directory(slug)?;
        authenticate(&directory, values, authorization)?;
        let value = required_token(values)?;
        let mut memory = self.memory()?;
        memory.prune(Utc::now());
        let id = &directory.environment.id;
        let (grant, mut response) = if let Some(token) = memory
            .access
            .get(value)
            .filter(|token| token.grant.environment == *id)
        {
            let mut response = json!({"active":true,"iss":issuer,"token_type":"Bearer","client_id":token.grant.client,
                "scope":token.grant.scope,"iat":token.issued.timestamp(),"exp":token.expires.timestamp(),"sub":token.grant.client});
            if !token.audience.is_empty() {
                response["aud"] = json!(token.audience);
            }
            (&token.grant, response)
        } else if let Some(token) = memory.refresh.get(value).filter(|token| {
            token.grant.environment == *id
                && token.grant.client == directory.environment.settings.oidc_client_id
        }) {
            (
                &token.grant,
                json!({"active":true,"iss":issuer,"client_id":token.grant.client,"scope":token.grant.scope,
                "iat":token.issued.timestamp(),"exp":token.expires.timestamp()}),
            )
        } else {
            return Ok(json!({"active":false}));
        };
        if !grant.user.is_empty() {
            let Some(user) = active_user(&directory, &grant.user) else {
                return Ok(json!({"active":false}));
            };
            response["sub"] = json!(user.id);
            response["username"] = json!(user.fields.username);
        }
        Ok(response)
    }
    pub fn revoke(&self, slug: &str, values: &Parameters, authorization: &str) -> Result<()> {
        let directory = self.directory(slug)?;
        authenticate(&directory, values, authorization)?;
        let value = required_token(values)?;
        let id = &directory.environment.id;
        let mut memory = self.memory()?;
        memory.prune(Utc::now());
        if memory
            .access
            .get(value)
            .is_some_and(|token| token.grant.environment == *id)
        {
            memory.access.remove(value);
        } else if let Some(token) = memory
            .refresh
            .get(value)
            .filter(|token| {
                token.grant.environment == *id
                    && token.grant.client == directory.environment.settings.oidc_client_id
            })
            .cloned()
        {
            memory.refresh.remove(value);
            if !token.grant.grant_id.is_empty() {
                memory.access.retain(|_, other| {
                    other.grant.environment != *id || other.grant.grant_id != token.grant.grant_id
                });
                memory.refresh.retain(|_, other| {
                    other.grant.environment != *id || other.grant.grant_id != token.grant.grant_id
                });
            }
        }
        memory.event(id, "revoke", "", "Client revoked a token");
        Ok(())
    }
    pub fn member_objects(
        &self,
        slug: &str,
        oid: &str,
        authorization: &str,
        body: &Value,
    ) -> Result<Value> {
        let directory = self.directory(slug)?;
        if directory.environment.settings.persona != "entra" {
            return Err(Error::NotFound("endpoint").into());
        }
        let mut memory = self.memory()?;
        memory.prune(Utc::now());
        let value = bearer_token(authorization).ok_or_else(|| {
            ProtocolError::unauthorized("InvalidAuthenticationToken", "Access token is empty.")
        })?;
        let access = memory
            .access
            .get(value)
            .filter(|access| access.grant.environment == directory.environment.id)
            .ok_or_else(|| {
                ProtocolError::unauthorized(
                    "InvalidAuthenticationToken",
                    "Access token is invalid or expired.",
                )
            })?;
        let user = active_user(&directory, &access.grant.user).ok_or_else(|| {
            ProtocolError::unauthorized(
                "InvalidAuthenticationToken",
                "User is inactive or missing.",
            )
        })?;
        if oid != claims::object_id(&directory.environment.id, &user.id)
            || !directory.environment.settings.include_groups_claim
            || !has_scope(&access.grant.scope, "groups")
        {
            return Err(ProtocolError {
                status: 403,
                ..ProtocolError::new(
                    "Authorization_RequestDenied",
                    "Insufficient privileges to complete the operation.",
                )
            });
        }
        if !body["securityEnabledOnly"].is_boolean() {
            return Err(ProtocolError::new(
                "Request_BadRequest",
                "The request body must set securityEnabledOnly.",
            ));
        }
        let groups = claims::groups(&directory, &user.id);
        memory.event(
            &directory.environment.id,
            "groups overage",
            &label(user),
            &format!("Served {} groups through getMemberObjects", groups.len()),
        );
        memory.note_groups(
            &directory,
            &user.id,
            "oidc",
            "group source response",
            &directory.environment.settings.oidc_client_id,
            lifecycle::IssuedGroups {
                groups: groups.clone(),
                carried: true,
                overage: false,
            },
        );
        Ok(
            json!({"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#Collection(Edm.String)","value":groups}),
        )
    }
}
fn required_token(values: &Parameters) -> Result<&str> {
    let value = param(values, "token");
    if value.is_empty() {
        return Err(ProtocolError::new("invalid_request", "token is required"));
    }
    Ok(value)
}
fn access_for<'a>(
    memory: &'a Memory,
    directory: &Directory,
    authorization: &str,
) -> Result<&'a Access> {
    let value = bearer_token(authorization).ok_or_else(|| {
        ProtocolError::unauthorized("invalid_token", "access token is invalid or expired")
    })?;
    memory
        .access
        .get(value)
        .filter(|access| access.grant.environment == directory.environment.id)
        .ok_or_else(|| {
            ProtocolError::unauthorized("invalid_token", "access token is invalid or expired")
        })
}
fn bearer_token(authorization: &str) -> Option<&str> {
    let (scheme, value) = authorization.trim().split_once(' ')?;
    (scheme.eq_ignore_ascii_case("Bearer")
        && !value.is_empty()
        && !value.contains(char::is_whitespace))
    .then_some(value)
}
pub(super) fn authenticate(
    directory: &Directory,
    values: &Parameters,
    authorization: &str,
) -> Result<()> {
    let settings = &directory.environment.settings;
    let basic = authorization
        .split_once(' ')
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Basic"))
        .and_then(|(_, value)| base64::engine::general_purpose::STANDARD.decode(value).ok())
        .and_then(|value| String::from_utf8(value).ok())
        .and_then(|value| {
            value
                .split_once(':')
                .map(|(a, b)| (a.to_owned(), b.to_owned()))
        });
    let used_basic = basic.is_some();
    let valid = if settings.oidc_public_client {
        param(values, "client_id") == settings.oidc_client_id
    } else {
        let (client, secret) = basic
            .map(|(a, b)| (decode_credential(&a), decode_credential(&b)))
            .unwrap_or_else(|| {
                (
                    param(values, "client_id").into(),
                    param(values, "client_secret").into(),
                )
            });
        client == settings.oidc_client_id && constant_equal(&secret, &settings.oidc_client_secret)
    };
    if valid {
        return Ok(());
    }
    Err(ProtocolError {
        basic_challenge: used_basic,
        ..ProtocolError::unauthorized("invalid_client", "client authentication failed")
    })
}
pub(super) fn valid_verifier(challenge: &str, verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
        && constant_equal(
            challenge,
            &URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
        )
}

fn decode_credential(value: &str) -> String {
    let mut bytes = Vec::with_capacity(value.len());
    let mut input = value.bytes();
    while let Some(byte) = input.next() {
        match byte {
            b'+' => bytes.push(b' '),
            b'%' => {
                let hex = input
                    .next()
                    .zip(input.next())
                    .and_then(|(a, b)| (a as char).to_digit(16).zip((b as char).to_digit(16)));
                let Some((a, b)) = hex else {
                    return value.into();
                };
                bytes.push((a * 16 + b) as u8);
            }
            byte => bytes.push(byte),
        }
    }
    String::from_utf8(bytes).unwrap_or_else(|_| value.into())
}
