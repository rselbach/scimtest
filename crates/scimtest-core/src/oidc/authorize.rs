use super::claims::{MFA_CONTEXTS, PASSWORD_CONTEXTS};
use super::*;
use url::Url;

pub enum Authorization {
    Code {
        code: String,
        redirect: String,
        state: String,
        session: String,
    },
    Redirect(String),
    Chooser {
        directory: Box<Directory>,
        options: ChooserOptions,
    },
}
#[derive(Default)]
pub(super) struct Request {
    pub(super) passive: bool,
    pub(super) fresh_reason: String,
    pub(super) max_age: Option<u32>,
    pub(super) contexts: Vec<String>,
}
impl Request {
    fn parse(directory: &Directory, values: &Parameters) -> Result<Self> {
        if param(values, "response_type") != "code" {
            return Err(ProtocolError::new(
                "unsupported_response_type",
                "response_type must be code",
            ));
        }
        if !has_scope(param(values, "scope"), "openid") {
            return Err(ProtocolError::new(
                "invalid_scope",
                "scope must include openid",
            ));
        }
        let challenge = param(values, "code_challenge");
        let method = param(values, "code_challenge_method");
        let problem = if directory.environment.settings.oidc_public_client && challenge.is_empty() {
            "public clients must use PKCE"
        } else if !challenge.is_empty() && method != "S256" {
            "code_challenge_method must be S256"
        } else if !challenge.is_empty() && challenge.len() != 43 {
            "code_challenge must be a valid S256 challenge"
        } else if challenge.is_empty() && !method.is_empty() {
            "code_challenge is required when code_challenge_method is set"
        } else {
            ""
        };
        if !problem.is_empty() {
            return Err(ProtocolError::new("invalid_request", problem));
        }
        let prompts = param(values, "prompt")
            .split_whitespace()
            .collect::<Vec<_>>();
        if prompts.contains(&"none") && prompts.len() > 1 {
            return Err(ProtocolError::new(
                "invalid_request",
                "prompt=none cannot be combined with other prompt values",
            ));
        }
        let max_age = match param(values, "max_age") {
            "" => None,
            value => Some(value.parse::<u32>().map_err(|_| {
                ProtocolError::new(
                    "invalid_request",
                    "max_age must be a non-negative number of seconds",
                )
            })?),
        };
        Ok(Self {
            passive: prompts.contains(&"none"),
            fresh_reason: if prompts.contains(&"login") {
                "prompt=login".into()
            } else if max_age == Some(0) {
                "max_age=0".into()
            } else {
                String::new()
            },
            max_age,
            contexts: param(values, "acr_values")
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
        })
    }
    pub(super) fn reusable(&self, authn: &Authn, now: DateTime<Utc>) -> bool {
        self.reuse_blocker(authn, now).is_none()
    }
    pub(super) fn reuse_blocker(&self, authn: &Authn, now: DateTime<Utc>) -> Option<String> {
        if !self.fresh_reason.is_empty() {
            return Some(self.fresh_reason.clone());
        }
        self.max_age
            .filter(|age| now - authn.time > Duration::seconds((*age).into()))
            .map(|age| format!("max_age={age}"))
    }
    pub(super) fn reused_session<'a>(
        &self,
        remembered: Option<&'a Session>,
        now: DateTime<Utc>,
    ) -> Result<&'a Session> {
        let session = remembered.ok_or_else(|| {
            ProtocolError::new("invalid_request", "there is no remembered sign-in to reuse")
        })?;
        if let Some(reason) = self.reuse_blocker(&session.authn, now) {
            return Err(ProtocolError::new(
                "invalid_request",
                &format!("the app requires a fresh sign-in ({reason})"),
            ));
        }
        Ok(session)
    }
    pub(super) fn authentication(&self, values: &Parameters, now: DateTime<Utc>) -> Result<Authn> {
        let requested = param(values, "authn_strength").trim();
        let strength = if !requested.is_empty() {
            requested
        } else {
            self.contexts
                .iter()
                .find_map(|context| {
                    if MFA_CONTEXTS.contains(&context.as_str()) {
                        Some("mfa")
                    } else if PASSWORD_CONTEXTS.contains(&context.as_str()) {
                        Some("password")
                    } else {
                        None
                    }
                })
                .unwrap_or("password")
        };
        let contexts = match strength {
            "password" => PASSWORD_CONTEXTS,
            "mfa" => MFA_CONTEXTS,
            _ => {
                return Err(ProtocolError::new(
                    "invalid_request",
                    "authn_strength must be one of password, mfa",
                ));
            }
        };
        let context = self
            .contexts
            .iter()
            .find(|context| contexts.contains(&context.as_str()))
            .map(String::as_str)
            .unwrap_or(contexts[0]);
        Ok(Authn {
            time: now,
            strength: strength.into(),
            context: context.into(),
        })
    }
}
impl Identity {
    pub fn authorize(
        &self,
        slug: &str,
        values: &Parameters,
        cookie: &str,
        local: bool,
        callback: &str,
        post: bool,
    ) -> Result<Authorization> {
        let directory = self.directory(slug)?;
        let environment = &directory.environment;
        let settings = &environment.settings;
        if param(values, "client_id") != settings.oidc_client_id {
            return Err(ProtocolError::new(
                "invalid_request",
                "client_id is invalid",
            ));
        }
        validate_redirect(&directory, param(values, "redirect_uri"), local, callback)?;
        let mut redirect = redirect_url(param(values, "redirect_uri"))?;
        let request = match Request::parse(&directory, values) {
            Ok(request) => request,
            Err(error) => {
                return Ok(Authorization::Redirect(error_redirect(
                    redirect, values, &error,
                )));
            }
        };
        if truthy(param(values, "deny")) {
            return Ok(Authorization::Redirect(error_redirect(
                redirect,
                values,
                &ProtocolError::new("access_denied", "the user denied the request"),
            )));
        }
        let now = Utc::now();
        let mut memory = self.memory()?;
        memory.prune(now);
        let remembered = memory
            .sessions
            .get(cookie)
            .filter(|session| {
                session.environment == environment.id
                    && active_user(&directory, &session.user).is_some()
            })
            .cloned();
        let reuse = request.passive || truthy(param(values, "continue_session"));
        if request.passive
            && remembered
                .as_ref()
                .is_none_or(|session| !request.reusable(&session.authn, now))
        {
            return Ok(Authorization::Redirect(error_redirect(
                redirect,
                values,
                &ProtocolError::new(
                    "login_required",
                    "prompt=none requires a reusable remembered sign-in",
                ),
            )));
        }
        let identifier_mode = settings.chooser_mode == "identifier";
        let selected = if identifier_mode {
            !param(values, "login_identifier").is_empty()
        } else {
            !param(values, "user_id").is_empty()
        };
        if !post && !reuse && !selected {
            let options = request.chooser_options(&directory, values, remembered.as_ref(), now, "");
            return Ok(Authorization::Chooser {
                directory: Box::new(directory),
                options,
            });
        }
        let (user, mut authn) = if reuse {
            let session = request.reused_session(remembered.as_ref(), now)?;
            (
                active_user(&directory, &session.user).unwrap(),
                session.authn.clone(),
            )
        } else {
            let user = selected_user(&directory, values)
                .ok_or_else(|| ProtocolError::new("invalid_request", "active user is required"))?;
            (user, request.authentication(values, now)?)
        };
        let contexts = if authn.strength == "mfa" {
            MFA_CONTEXTS
        } else {
            PASSWORD_CONTEXTS
        };
        authn.context = request
            .contexts
            .iter()
            .find(|context| contexts.contains(&context.as_str()))
            .map(String::as_str)
            .unwrap_or(contexts[0])
            .into();
        let session = memory.join_session(environment, user, authn.clone(), cookie, "oidc", now);
        let faults = memory.flow_faults(&environment.id, values);
        let code = random_secret(24);
        let grant = Grant {
            environment: environment.id.clone(),
            client: settings.oidc_client_id.clone(),
            user: user.id.clone(),
            redirect: param(values, "redirect_uri").into(),
            nonce: param(values, "nonce").into(),
            scope: param(values, "scope").into(),
            challenge: param(values, "code_challenge").into(),
            authn,
            session: session.id.clone(),
            grant_id: String::new(),
            expires: now + Duration::minutes(5),
            faults,
        };
        memory.inspection(&grant, user, "Authorization code issued", &Value::Null, "")?;
        memory.codes.insert(code.clone(), grant);
        memory.event(
            &environment.id,
            "authorize",
            &label(user),
            "Authorization code issued",
        );
        set_query(&mut redirect, "code", &code);
        if !param(values, "state").is_empty() {
            set_query(&mut redirect, "state", param(values, "state"));
        }
        Ok(Authorization::Code {
            code,
            redirect: redirect.to_string(),
            state: param(values, "state").into(),
            session: session.id,
        })
    }
}
pub(super) fn validate_redirect(
    directory: &Directory,
    value: &str,
    local: bool,
    callback: &str,
) -> Result<()> {
    redirect_url(value)?;
    let settings = &directory.environment.settings;
    if !(local && (settings.allow_any_oidc_redirect || !callback.is_empty() && value == callback))
        && !settings.oidc_redirect_uris.iter().any(|uri| uri == value)
    {
        return Err(ProtocolError::new(
            "invalid_request",
            "redirect_uri is not registered for this app",
        ));
    }
    Ok(())
}
pub(super) fn redirect_url(value: &str) -> Result<Url> {
    Url::parse(value)
        .ok()
        .filter(|url| {
            ["http", "https"].contains(&url.scheme())
                && url.has_host()
                && url.fragment().is_none_or(str::is_empty)
        })
        .ok_or_else(|| {
            ProtocolError::new(
                "invalid_request",
                "redirect_uri must be a valid absolute HTTP(S) URL without a fragment",
            )
        })
}
pub(super) fn set_query(url: &mut Url, name: &str, value: &str) {
    let mut pairs = url
        .query_pairs()
        .filter(|(key, _)| key != name)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    pairs.push((name.into(), value.into()));
    url.query_pairs_mut().clear().extend_pairs(pairs);
}
fn error_redirect(mut url: Url, values: &Parameters, error: &ProtocolError) -> String {
    set_query(&mut url, "error", &error.code);
    set_query(&mut url, "error_description", &error.description);
    if !param(values, "state").is_empty() {
        set_query(&mut url, "state", param(values, "state"));
    }
    url.into()
}
