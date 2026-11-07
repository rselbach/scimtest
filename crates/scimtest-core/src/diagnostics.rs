use crate::Error;
use axum::http::{HeaderMap, StatusCode, Version};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::VecDeque,
    sync::{Arc, LazyLock, Mutex},
};

#[derive(Clone, Copy, Default)]
pub struct Settings {
    pub debug: bool,
    pub record: bool,
    pub record_secrets: bool,
}
#[derive(Clone, Default, Serialize)]
pub struct Snapshot {
    pub record: bool,
    pub record_secrets: bool,
    pub entries: Vec<String>,
}
#[derive(Default)]
struct State {
    settings: Settings,
    entries: VecDeque<String>,
}
struct Inner {
    state: Mutex<State>,
    revision: tokio::sync::watch::Sender<u64>,
}
#[derive(Clone)]
pub struct Diagnostics(Arc<Inner>);
impl Default for Diagnostics {
    fn default() -> Self {
        let (revision, _) = tokio::sync::watch::channel(0);
        Self(Arc::new(Inner {
            state: Mutex::new(State::default()),
            revision,
        }))
    }
}
impl Diagnostics {
    pub(crate) fn saml_logout(
        &self,
        outcome: &str,
        messages: &[(&str, &str)],
    ) -> Result<(), Error> {
        let settings = self.settings()?;
        if !settings.debug && !settings.record {
            return Ok(());
        }
        let mut text = format!(
            "===== SAML Single Logout {} =====\n",
            chrono::Utc::now().to_rfc3339()
        );
        for (heading, xml) in messages {
            text.push_str(&format!("----- {heading} -----\n{xml}\n"));
        }
        text.push_str(&format!(
            "----- outcome -----\n{outcome}\n===== end SAML Single Logout ====="
        ));
        self.record(text, settings)
    }
    pub(crate) fn backchannel(
        &self,
        uri: &str,
        token: &str,
        status: Option<StatusCode>,
        headers: &HeaderMap,
        response: &[u8],
    ) -> Result<(), Error> {
        let settings = self.settings()?;
        if !settings.debug && !settings.record {
            return Ok(());
        }
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("logout_token", token)
            .finish();
        let mut request_headers = HeaderMap::new();
        request_headers.insert(
            "content-type",
            axum::http::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        self.record(
            transcript(
                Exchange {
                    title: "Back-channel logout",
                    method: "POST",
                    uri,
                    version: Version::HTTP_11,
                    request_headers: &request_headers,
                    request_body: body.as_bytes(),
                    status,
                    response_headers: headers,
                    response_body: response,
                },
                settings,
            ),
            settings,
        )
    }
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.0.revision.subscribe()
    }
    pub fn settings(&self) -> Result<Settings, Error> {
        Ok(self.0.state.lock().map_err(|_| Error::Lock)?.settings)
    }
    pub fn snapshot(&self) -> Result<Snapshot, Error> {
        let state = self.0.state.lock().map_err(|_| Error::Lock)?;
        Ok(Snapshot {
            record: state.settings.record,
            record_secrets: state.settings.record_secrets,
            entries: state.entries.iter().cloned().collect(),
        })
    }
    pub fn update(
        &self,
        debug: Option<bool>,
        record: Option<bool>,
        secrets: Option<bool>,
    ) -> Result<(), Error> {
        let mut state = self.0.state.lock().map_err(|_| Error::Lock)?;
        if let Some(debug) = debug {
            state.settings.debug = debug;
        }
        if let Some(record) = record {
            state.settings.record = record;
        }
        if let Some(secrets) = secrets {
            state.settings.record_secrets = secrets;
        }
        state.settings.record_secrets &= state.settings.record;
        drop(state);
        self.changed();
        Ok(())
    }
    pub fn clear(&self) -> Result<(), Error> {
        self.0
            .state
            .lock()
            .map_err(|_| Error::Lock)?
            .entries
            .clear();
        self.changed();
        Ok(())
    }
    pub(crate) fn record(&self, text: String, settings: Settings) -> Result<(), Error> {
        if settings.debug {
            use std::io::Write;
            let mut output = std::io::stdout().lock();
            writeln!(output, "\n{text}")?;
        }
        if settings.record {
            let mut state = self.0.state.lock().map_err(|_| Error::Lock)?;
            state.entries.push_front(text);
            state.entries.truncate(100);
            drop(state);
            self.changed();
        }
        Ok(())
    }
    fn changed(&self) {
        self.0
            .revision
            .send_modify(|value| *value = value.wrapping_add(1));
    }
}

pub(crate) struct Exchange<'a> {
    pub title: &'a str,
    pub method: &'a str,
    pub uri: &'a str,
    pub version: Version,
    pub request_headers: &'a HeaderMap,
    pub request_body: &'a [u8],
    pub status: Option<StatusCode>,
    pub response_headers: &'a HeaderMap,
    pub response_body: &'a [u8],
}
pub(crate) fn transcript(exchange: Exchange<'_>, settings: Settings) -> String {
    let secrets = settings.record_secrets;
    let uri = if secrets {
        exchange.uri.into()
    } else {
        redact_url(exchange.uri)
    };
    let request_heading = if exchange.title == "Back-channel logout" {
        "request to app"
    } else {
        "request from RP"
    };
    let response_heading = if exchange.title == "Back-channel logout" {
        "response from app"
    } else {
        "response to RP"
    };
    let mut output = format!(
        "===== {} {} =====\n----- {request_heading} -----\n{} {} {:?}\n",
        exchange.title,
        chrono::Utc::now().to_rfc3339(),
        exchange.method,
        uri,
        exchange.version
    );
    write_headers(&mut output, exchange.request_headers, secrets);
    if !exchange.request_body.is_empty() {
        output.push('\n');
        output.push_str(&body(
            content_type(exchange.request_headers),
            exchange.request_body,
            secrets,
        ));
        output.push('\n');
    }
    if let Some((_, query)) = exchange.uri.split_once('?') {
        decoded_form(&mut output, query, secrets);
    }
    if content_type(exchange.request_headers).starts_with("application/x-www-form-urlencoded") {
        decoded_form(
            &mut output,
            &String::from_utf8_lossy(exchange.request_body),
            secrets,
        );
    }
    if let Some(status) = exchange.status {
        output.push_str(&format!(
            "----- {response_heading} -----\nHTTP {} {}\n",
            status.as_u16(),
            status.canonical_reason().unwrap_or_default()
        ));
    } else {
        output.push_str("----- no response -----\n");
    }
    write_headers(&mut output, exchange.response_headers, secrets);
    if !exchange.response_body.is_empty() {
        output.push('\n');
        output.push_str(&body(
            content_type(exchange.response_headers),
            exchange.response_body,
            secrets,
        ));
        output.push('\n');
    }
    let response = String::from_utf8_lossy(exchange.response_body);
    for (name, value) in hidden_values(&response) {
        if name.eq_ignore_ascii_case("SAMLRequest")
            || secrets && name.eq_ignore_ascii_case("SAMLResponse")
        {
            decoded_saml(&mut output, &name, &value);
        }
    }
    if let Some(location) = exchange
        .response_headers
        .get("location")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once('?').map(|(_, query)| query))
    {
        decoded_form(&mut output, location, secrets);
    }
    if secrets
        && let Ok(Value::Object(values)) = serde_json::from_slice::<Value>(exchange.response_body)
    {
        for name in ["id_token", "access_token"] {
            if let Some(token) = values.get(name).and_then(Value::as_str) {
                decoded_jwt(&mut output, name, token);
            }
        }
    }
    output.push_str(&format!("===== end {} =====", exchange.title));
    output
}
fn content_type(headers: &HeaderMap) -> &str {
    headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
}
fn write_headers(output: &mut String, headers: &HeaderMap, secrets: bool) {
    let mut names = headers.keys().map(|name| name.as_str()).collect::<Vec<_>>();
    names.sort_unstable();
    for name in names {
        for value in headers.get_all(name) {
            let value = value.to_str().unwrap_or("[binary header]");
            let value = if !secrets
                && [
                    "authorization",
                    "proxy-authorization",
                    "cookie",
                    "set-cookie",
                    "x-scimtest-instance-token",
                ]
                .contains(&name)
            {
                "[REDACTED]".into()
            } else if !secrets && name == "location" {
                redact_url(value)
            } else {
                value.into()
            };
            output.push_str(&format!("{name}: {value}\n"));
        }
    }
}
fn sensitive(name: &str) -> bool {
    [
        "client_secret",
        "code",
        "code_verifier",
        "access_token",
        "id_token",
        "id_token_hint",
        "refresh_token",
        "logout_token",
        "token",
        "assertion",
        "samlresponse",
    ]
    .contains(&name.to_ascii_lowercase().as_str())
}
fn redact_form(value: &str) -> String {
    let mut output = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in url::form_urlencoded::parse(value.as_bytes()) {
        output.append_pair(
            &key,
            if sensitive(&key) {
                "[REDACTED]"
            } else {
                &value
            },
        );
    }
    output.finish()
}
fn redact_url(value: &str) -> String {
    let Some((path, query)) = value.split_once('?') else {
        return value.into();
    };
    if !url::form_urlencoded::parse(query.as_bytes()).any(|(name, _)| sensitive(&name)) {
        return value.into();
    }
    format!("{path}?{}", redact_form(query))
}
fn body(content_type: &str, bytes: &[u8], secrets: bool) -> String {
    let text = String::from_utf8_lossy(bytes);
    if secrets {
        return text.into();
    }
    if content_type
        .to_ascii_lowercase()
        .starts_with("application/x-www-form-urlencoded")
    {
        return redact_form(&text);
    }
    if content_type
        .to_ascii_lowercase()
        .starts_with("application/json")
    {
        let Ok(mut value) = serde_json::from_slice::<Value>(bytes) else {
            return "[malformed JSON omitted while secrets are hidden]".into();
        };
        redact_json(&mut value);
        return serde_json::to_string_pretty(&value)
            .unwrap_or_else(|_| "[unavailable JSON]".into());
    }
    INPUT
        .replace_all(&text, |captures: &regex::Captures<'_>| {
            let tag = &captures[0];
            let name = attributes(tag)
                .into_iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("name"))
                .map(|(_, value)| value);
            if !name.as_ref().is_some_and(|name| sensitive(name)) {
                return tag.to_owned();
            }
            ATTRIBUTE
                .replace_all(tag, |attribute: &regex::Captures<'_>| {
                    if attribute[1].eq_ignore_ascii_case("value") {
                        "value=\"[REDACTED]\"".into()
                    } else {
                        attribute[0].to_owned()
                    }
                })
                .into_owned()
        })
        .into_owned()
}
fn redact_json(value: &mut Value) {
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                if sensitive(key) {
                    *value = Value::String("[REDACTED]".into());
                } else {
                    redact_json(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_json(value);
            }
        }
        _ => {}
    }
}
static INPUT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<input\b[^>]*>").expect("valid input pattern"));
static ATTRIBUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\b(name|value)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#)
        .expect("valid attribute pattern")
});
fn attributes(tag: &str) -> Vec<(String, String)> {
    ATTRIBUTE
        .captures_iter(tag)
        .map(|attribute| {
            (
                attribute[1].into(),
                attribute
                    .get(2)
                    .or_else(|| attribute.get(3))
                    .or_else(|| attribute.get(4))
                    .map(|value| value.as_str())
                    .unwrap_or_default()
                    .into(),
            )
        })
        .collect()
}
fn hidden_values(html: &str) -> Vec<(String, String)> {
    INPUT
        .find_iter(html)
        .filter_map(|tag| {
            let attributes = attributes(tag.as_str());
            let name = attributes
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("name"))?
                .1
                .clone();
            let value = attributes
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("value"))?
                .1
                .clone();
            Some((name, value))
        })
        .collect()
}
fn decoded_form(output: &mut String, query: &str, secrets: bool) {
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if key == "SAMLRequest" || key == "SAMLResponse" && secrets {
            decoded_saml(output, &key, &value);
        }
        if key == "logout_token" {
            decoded_jwt(output, &key, &value);
        }
    }
}
fn decoded_saml(output: &mut String, name: &str, value: &str) {
    if let Ok(xml) = crate::saml::decode_message(value) {
        output.push_str(&format!("\n----- decoded {name} -----\n{xml}\n"));
    }
}
fn decoded_jwt(output: &mut String, name: &str, value: &str) {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return;
    }
    let decoded = parts[..2]
        .iter()
        .map(|part| {
            URL_SAFE_NO_PAD
                .decode(part)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        })
        .collect::<Option<Vec<_>>>();
    if let Some(decoded) = decoded {
        output.push_str(&format!(
            "\n----- decoded {name} -----\n{}\n{}\n",
            decoded[0], decoded[1]
        ));
    }
}
