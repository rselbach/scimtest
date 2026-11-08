use crate::{
    enrollment::{EnrollmentState, Hash},
    lock, network,
    server::{State, error, text_response},
    store::Session,
};
use anyhow::Result;
use axum::{
    body::to_bytes,
    extract::Request,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, net::SocketAddr, time::Duration as StdDuration};
use subtle::ConstantTimeEq;
use url::Url;

#[cfg(test)]
mod tests;

pub(crate) const STATE_COOKIE: &str = "scimtest_oauth_state";
pub(crate) const SESSION_COOKIE: &str = "scimtest_session";
const AUTHORIZE_URL: &str = "https://github.com/login/oauth/authorize";

pub(crate) struct GitHubClient {
    pub client: reqwest::Client,
    pub authorize_url: String,
    pub token_url: String,
    pub user_url: String,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct GitHubUser {
    pub id: i64,
    pub login: String,
}

#[derive(Clone)]
pub(crate) struct OAuthIntent {
    pub enrollment: Option<Hash>,
    verifier: String,
    ip: String,
    expires_at: chrono::DateTime<Utc>,
}

impl GitHubClient {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(StdDuration::from_secs(15))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            authorize_url: AUTHORIZE_URL.into(),
            token_url: "https://github.com/login/oauth/access_token".into(),
            user_url: "https://api.github.com/user".into(),
        })
    }

    async fn user(
        &self,
        state: &State,
        code: &str,
        verifier: &str,
    ) -> std::result::Result<GitHubUser, &'static str> {
        #[derive(Deserialize)]
        struct Token {
            #[serde(default)]
            access_token: String,
            #[serde(default)]
            error: String,
        }
        let callback = state.callback_url();
        let response = self
            .client
            .post(&self.token_url)
            .header("accept", "application/json")
            .header("user-agent", "scimtest-server")
            .form(&[
                ("client_id", state.config.github_client_id.as_str()),
                ("client_secret", state.config.github_client_secret.as_str()),
                ("code", code),
                ("redirect_uri", &callback),
                ("code_verifier", verifier),
            ])
            .send()
            .await
            .map_err(|_| "GitHub token exchange failed")?;
        if !response.status().is_success() {
            return Err("GitHub token exchange failed");
        }
        let token = response
            .json::<Token>()
            .await
            .map_err(|_| "GitHub token exchange failed")?;
        if !token.error.is_empty() || token.access_token.is_empty() {
            return Err("GitHub token exchange failed");
        }
        let response = self
            .client
            .get(&self.user_url)
            .header("accept", "application/vnd.github+json")
            .header("user-agent", "scimtest-server")
            .bearer_auth(token.access_token)
            .send()
            .await
            .map_err(|_| "GitHub user lookup failed")?;
        if response.status() != reqwest::StatusCode::OK {
            return Err("GitHub user lookup failed");
        }
        let user = response
            .json::<GitHubUser>()
            .await
            .map_err(|_| "GitHub user lookup failed")?;
        if user.id <= 0 || user.login.trim().is_empty() {
            return Err("GitHub user lookup failed");
        }
        Ok(user)
    }
}

impl State {
    pub fn github_configured(&self) -> bool {
        !self.config.github_client_id.is_empty() && !self.config.github_client_secret.is_empty()
    }

    pub fn callback_url(&self) -> String {
        format!(
            "{}://{}/auth/github/callback",
            self.config.public_scheme, self.config.dashboard_domain
        )
    }

    pub fn secure_cookie(&self) -> bool {
        self.config.public_scheme == "https" || self.config.behind_proxy
    }

    pub fn cookie_name(&self, name: &str) -> String {
        if self.secure_cookie() {
            format!("__Host-{name}")
        } else {
            name.into()
        }
    }

    pub fn set_cookie(&self, response: &mut Response, name: &str, value: &str, attributes: &str) {
        let cookie = format!(
            "{}={value}; Path=/; HttpOnly; SameSite={attributes}{}",
            self.cookie_name(name),
            if self.secure_cookie() { "; Secure" } else { "" }
        );
        if let Ok(cookie) = HeaderValue::from_str(&cookie) {
            response.headers_mut().append("set-cookie", cookie);
        }
    }

    pub fn clear_cookie(&self, response: &mut Response, name: &str) {
        self.set_cookie(
            response,
            name,
            "",
            "Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        );
    }

    pub fn begin_oauth(
        &self,
        request: &Request,
        peer: SocketAddr,
        enrollment: Option<Hash>,
    ) -> Result<Response> {
        if !self.github_configured() {
            return Ok(error(
                StatusCode::SERVICE_UNAVAILABLE,
                "GitHub OAuth is not configured",
            ));
        }
        let state = random_hex(24)?;
        let verifier = random_hex(32)?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let ip = network::enrollment_ip(&network::client_ip(
            peer,
            request.headers(),
            self.config.behind_proxy,
            &self.trusted,
        ));
        let now = Utc::now();
        {
            let mut pending = lock(&self.enrollment);
            pending.prune(now);
            if let Some(hash) = enrollment {
                pending
                    .oauth
                    .retain(|_, intent| intent.enrollment != Some(hash));
            }
            if pending
                .oauth
                .values()
                .filter(|intent| intent.ip == ip)
                .count()
                >= 20
            {
                return Ok(error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many pending logins from this network; try again later",
                ));
            }
            if pending.oauth.len() >= 1000
                && let Some(oldest) = pending
                    .oauth
                    .iter()
                    .min_by_key(|(_, intent)| intent.expires_at)
                    .map(|(key, _)| key.clone())
            {
                pending.oauth.remove(&oldest);
            }
            pending.oauth.insert(
                state.clone(),
                OAuthIntent {
                    enrollment,
                    verifier,
                    ip,
                    expires_at: now + Duration::minutes(10),
                },
            );
        }
        let mut url = Url::parse(&self.github.authorize_url)?;
        url.query_pairs_mut().extend_pairs([
            ("client_id", self.config.github_client_id.as_str()),
            ("state", &state),
            ("redirect_uri", &self.callback_url()),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ]);
        let mut response = redirect(url.as_str());
        self.set_cookie(&mut response, STATE_COOKIE, &state, "Lax; Max-Age=600");
        Ok(response)
    }

    pub async fn oauth_callback(&self, request: Request) -> Response {
        let query = query(&request);
        let state = field(&query, "state");
        if !equal_secret(
            cookie(request.headers(), &self.cookie_name(STATE_COOKIE)).unwrap_or(""),
            state,
        ) {
            return error(StatusCode::BAD_REQUEST, "invalid login state");
        }
        let intent = {
            let mut pending = lock(&self.enrollment);
            pending.prune(Utc::now());
            pending.oauth.remove(state)
        };
        let mut response = self.finish_oauth(intent, field(&query, "code")).await;
        self.clear_cookie(&mut response, STATE_COOKIE);
        response
    }

    async fn finish_oauth(&self, intent: Option<OAuthIntent>, code: &str) -> Response {
        let Some(intent) = intent else {
            return error(StatusCode::BAD_REQUEST, "invalid or expired login state");
        };
        if code.is_empty() {
            return error(StatusCode::BAD_REQUEST, "missing code");
        }
        let user = match self.github.user(self, code, &intent.verifier).await {
            Ok(user) => user,
            Err(message) => return error(StatusCode::BAD_GATEWAY, message),
        };
        if let Some(hash) = intent.enrollment {
            return self.approve_or_replace(hash, user);
        }
        if user.login.trim().to_lowercase() != "rselbach" {
            return error(
                StatusCode::FORBIDDEN,
                "Your GitHub user is not allowed to manage scimtest-server.",
            );
        }
        let session = match self.store.create_session("rselbach", true) {
            Ok(session) => session,
            Err(_) => {
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not create session",
                );
            }
        };
        let mut response = redirect("/dashboard");
        self.set_cookie(
            &mut response,
            SESSION_COOKIE,
            &session.id,
            &format!(
                "Lax; Expires={}",
                session.expires_at.format("%a, %d %b %Y %H:%M:%S GMT")
            ),
        );
        response
    }

    pub fn require_session(
        &self,
        request: &Request,
    ) -> std::result::Result<Session, Box<Response>> {
        let Some(id) = cookie(request.headers(), &self.cookie_name(SESSION_COOKIE)) else {
            return Err(Box::new(redirect("/login/github")));
        };
        match self.store.session(id) {
            Ok(Some(session)) => Ok(session),
            Ok(None) => {
                let mut response = redirect("/login/github");
                self.clear_cookie(&mut response, SESSION_COOKIE);
                Err(Box::new(response))
            }
            Err(_) => Err(Box::new(error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not load session",
            ))),
        }
    }

    pub fn allowed_mutation(&self, request: &Request) -> bool {
        let origin = header(request.headers(), "origin").trim();
        let expected = format!(
            "{}://{}",
            self.config.public_scheme, self.config.dashboard_domain
        );
        let parsed = parse_origin(origin);
        if let Some((url, path)) = &parsed
            && path.is_empty()
            && let Ok(expected) = Url::parse(&expected)
            && url.scheme() == expected.scheme()
            && url.host_str() == expected.host_str()
            && url.port_or_known_default() == expected.port_or_known_default()
        {
            return true;
        }
        let host = header(request.headers(), "host");
        if !self.dashboard_host(host) {
            return false;
        }
        if origin.is_empty() {
            return header(request.headers(), "sec-fetch-site") == "same-origin";
        }
        let Some((url, path)) = parsed else {
            return false;
        };
        if !path.trim_matches('/').is_empty() {
            return false;
        }
        if header(request.headers(), "sec-fetch-site") == "cross-site" {
            return false;
        }
        Url::parse(&format!("{}://{host}", url.scheme())).is_ok_and(|host| {
            network::same_host(host.host_str().unwrap_or(""), url.host_str().unwrap_or(""))
                && host.port_or_known_default() == url.port_or_known_default()
        })
    }
}

fn parse_origin(value: &str) -> Option<(Url, String)> {
    if value.chars().any(|ch| ch.is_ascii_control()) {
        return None;
    }
    let (_, rest) = value.split_once("://")?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    if rest[..authority_end].contains('@') {
        return None;
    }
    let path = rest[authority_end..].split(['?', '#']).next().unwrap_or("");
    let path = percent_encoding::percent_decode_str(path)
        .decode_utf8_lossy()
        .into_owned();
    let url = Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.query().unwrap_or("").is_empty()
        || !url.fragment().unwrap_or("").is_empty()
    {
        return None;
    }
    Some((url, path))
}

impl EnrollmentState {
    pub fn prune_oauth(&mut self, now: chrono::DateTime<Utc>) {
        self.oauth.retain(|_, intent| now < intent.expires_at);
    }
}

pub(crate) fn random_hex(bytes: usize) -> Result<String> {
    let mut random = vec![0; bytes];
    rand::rngs::OsRng.try_fill_bytes(&mut random)?;
    Ok(random
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub(crate) fn equal_secret(left: &str, right: &str) -> bool {
    !left.is_empty() && bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

pub(crate) fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all("cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == name).then(|| {
                value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .unwrap_or(value)
            })
        })
}

pub(crate) fn header<'a>(headers: &'a HeaderMap, key: &str) -> &'a str {
    headers
        .get(key)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
}

pub(crate) type Form = BTreeMap<String, String>;

fn decode_form(value: &[u8]) -> (Form, Option<String>) {
    let mut form = Form::new();
    let mut error = None;
    for pair in value.split(|byte| *byte == b'&') {
        if pair.contains(&b';') {
            error = Some("invalid semicolon separator in query".into());
            continue;
        }
        if let Some(escape) = invalid_escape(pair) {
            error.get_or_insert_with(|| format!("invalid URL escape {escape:?}"));
            continue;
        }
        match serde_urlencoded::from_bytes::<Vec<(String, String)>>(pair) {
            Ok(pairs) => {
                for (key, value) in pairs {
                    form.entry(key).or_insert(value);
                }
            }
            Err(failure) => {
                error.get_or_insert_with(|| failure.to_string());
            }
        }
    }
    (form, error)
}

fn invalid_escape(value: &[u8]) -> Option<String> {
    let mut index = 0;
    while index < value.len() {
        if value[index] != b'%' {
            index += 1;
            continue;
        }
        if index + 2 >= value.len()
            || !value[index + 1..index + 3]
                .iter()
                .all(u8::is_ascii_hexdigit)
        {
            return Some(
                String::from_utf8_lossy(&value[index..value.len().min(index + 3)]).into_owned(),
            );
        }
        index += 3;
    }
    None
}

pub(crate) fn query(request: &Request) -> Form {
    decode_form(request.uri().query().unwrap_or("").as_bytes()).0
}

pub(crate) async fn form(request: Request, limit: usize) -> Result<Form> {
    if !header(request.headers(), "content-type")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    {
        return Ok(Form::new());
    }
    let (values, error) = decode_form(&to_bytes(request.into_body(), limit).await?);
    if let Some(error) = error {
        return Err(anyhow::anyhow!(error));
    }
    Ok(values)
}

pub(crate) fn field<'a>(form: &'a Form, key: &str) -> &'a str {
    form.get(key).map_or("", String::as_str)
}

pub(crate) fn redirect(location: &str) -> Response {
    let mut response = text_response(StatusCode::FOUND, "text/html; charset=utf-8", "");
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert("location", value);
    }
    response
}

pub(crate) fn method_not_allowed(methods: &'static str) -> Response {
    let mut response = error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    response
        .headers_mut()
        .insert("allow", HeaderValue::from_static(methods));
    response
}
