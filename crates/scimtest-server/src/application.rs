use anyhow::{Result, bail};
use base64::{
    Engine, alphabet,
    engine::{GeneralPurpose, GeneralPurposeConfig, general_purpose::STANDARD_NO_PAD},
};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, time::Instant};

#[cfg(test)]
mod tests;

pub const MAX_ROUTES: usize = 100;
pub const MAX_INSTANCES: usize = 1000;
pub const INSTANCE_MAX_IDLE_DAYS: i64 = 90;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default)]
pub struct Route {
    #[serde(deserialize_with = "crate::null_default")]
    pub methods: Vec<String>,
    pub path: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default)]
pub struct ApplicationSettings {
    pub name: String,
    pub public_key: String,
    #[serde(deserialize_with = "crate::null_default")]
    pub routes: Vec<Route>,
    pub requests_per_minute: i64,
    pub request_burst: i64,
    pub concurrent_requests: i64,
}

impl ApplicationSettings {
    pub(crate) fn validate(mut self) -> Result<(Self, String)> {
        self.name = self.name.split_whitespace().collect::<Vec<_>>().join(" ");
        if self.name.is_empty() {
            bail!("application name is required");
        }
        if self.name.len() > 80 {
            bail!("application name must be 80 characters or less");
        }
        let key = parse_public_key(&self.public_key)?;
        self.public_key = key.canonical;
        if self.routes.is_empty() {
            bail!("at least one route is required");
        }
        if self.requests_per_minute <= 0 || self.request_burst <= 0 || self.concurrent_requests <= 0
        {
            bail!("application limits must be positive");
        }
        Ok((self, key.fingerprint))
    }
}

pub fn valid_application_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn valid_instance_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub fn parse_routes(raw: &str) -> Result<Vec<Route>> {
    let mut routes = Vec::new();
    for (index, line) in raw.lines().enumerate() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        if fields.len() != 2 {
            bail!("route line {} must be METHODS PATH", index + 1);
        }
        let methods = parse_methods(fields[0])
            .map_err(|error| anyhow::anyhow!("route line {}: {error}", index + 1))?;
        validate_path(fields[1])
            .map_err(|error| anyhow::anyhow!("route line {}: {error}", index + 1))?;
        routes.push(Route {
            methods,
            path: fields[1].into(),
        });
    }
    if routes.is_empty() {
        bail!("at least one route is required");
    }
    if routes.len() > MAX_ROUTES {
        bail!("applications cannot have more than {MAX_ROUTES} routes");
    }
    Ok(routes)
}

fn parse_methods(raw: &str) -> Result<Vec<String>> {
    let mut methods = BTreeSet::new();
    for part in raw.split(',') {
        let part = part.trim();
        let method: String = part.chars().map(simple_uppercase).collect();
        if method.is_empty() {
            bail!("method is required");
        }
        if method != "*" && !method.bytes().all(http_token) {
            bail!("invalid method {}", quote(&method));
        }
        methods.insert(method);
    }
    Ok(methods.into_iter().collect())
}

fn simple_uppercase(ch: char) -> char {
    let mut upper = ch.to_uppercase();
    let first = upper.next().expect("uppercase mapping is nonempty");
    if upper.next().is_none() {
        return first;
    }
    // Go uses simple Unicode casing; Rust expands these Greek characters.
    match ch as u32 {
        0x1f80..=0x1f87 | 0x1f90..=0x1f97 | 0x1fa0..=0x1fa7 => {
            char::from_u32(ch as u32 + 8).expect("Greek uppercase range")
        }
        0x1fb3 => '\u{1fbc}',
        0x1fc3 => '\u{1fcc}',
        0x1ff3 => '\u{1ffc}',
        _ => ch,
    }
}

fn http_token(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn parameter(value: &str) -> bool {
    let Some(name) = value
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
    else {
        return false;
    };
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub(crate) fn validate_path(value: &str) -> Result<()> {
    if !value.starts_with('/') {
        bail!("path must start with /");
    }
    if value != "/" && value.ends_with('/') {
        bail!("trailing slashes are not allowed");
    }
    if value.contains("//") || value.contains('\\') {
        bail!("path contains an ambiguous separator");
    }
    for segment in value[1..].split('/') {
        if matches!(segment, "." | "..") {
            bail!("dot path segments are not allowed");
        }
        if segment.contains('*') {
            bail!("wildcards are not allowed; use a full {{name}} segment");
        }
        if segment.contains(['{', '}']) && !parameter(segment) {
            bail!("invalid path parameter {}", quote(segment));
        }
    }
    Ok(())
}

fn quote(value: &str) -> String {
    let mut quoted = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\u{7}' => quoted.push_str("\\a"),
            '\u{8}' => quoted.push_str("\\b"),
            '\u{b}' => quoted.push_str("\\v"),
            '\u{c}' => quoted.push_str("\\f"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '\u{0}'..='\u{1f}' | '\u{7f}' => quoted.push_str(&format!("\\x{:02x}", ch as u32)),
            _ if ch.escape_debug().to_string().starts_with("\\u{") => {
                quoted.push_str(&if ch as u32 <= 0xffff {
                    format!("\\u{:04x}", ch as u32)
                } else {
                    format!("\\U{:08x}", ch as u32)
                });
            }
            _ => quoted.push(ch),
        }
    }
    quoted.push('"');
    quoted
}

/// Check the original escaped request path before matching its decoded segments.
pub fn request_allowed(routes: &[Route], root: &str, method: &str, escaped_path: &str) -> bool {
    let lower = escaped_path.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") {
        return false;
    }
    let decoded = percent_decode_str(escaped_path).collect::<Vec<_>>();
    if decoded.first() != Some(&b'/') || decoded.contains(&b'\\') {
        return false;
    }
    if decoded != b"/"
        && decoded[1..]
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || matches!(part, b"." | b".."))
    {
        return false;
    }
    let Some(relative) = decoded.strip_prefix(root.as_bytes()) else {
        return false;
    };
    if !relative.is_empty() && relative[0] != b'/' {
        return false;
    }
    let path = if relative.is_empty() { b"/" } else { relative };
    routes.iter().any(|route| {
        route
            .methods
            .iter()
            .any(|allowed| allowed == "*" || allowed == method)
            && path_matches(&route.path, path)
    })
}

fn path_matches(pattern: &str, value: &[u8]) -> bool {
    let patterns: Vec<_> = pattern
        .strip_prefix('/')
        .unwrap_or(pattern)
        .split('/')
        .collect();
    let values: Vec<_> = value
        .strip_prefix(b"/")
        .unwrap_or(value)
        .split(|byte| *byte == b'/')
        .collect();
    patterns.len() == values.len()
        && patterns.iter().zip(values).all(|(pattern, value)| {
            if parameter(pattern) {
                !value.is_empty()
            } else {
                pattern.as_bytes() == value
            }
        })
}

#[derive(Debug)]
pub struct PublicKey {
    pub canonical: String,
    pub bytes: [u8; 32],
    pub fingerprint: String,
}

fn standard_base64(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    )
    .decode(value.replace(['\r', '\n'], ""))
}

pub fn parse_public_key(value: &str) -> Result<PublicKey> {
    let mut fields = value.split_whitespace();
    if fields.next() != Some("ssh-ed25519") {
        bail!("public key must be an ssh-ed25519 key");
    }
    let Some(encoded) = fields.next() else {
        bail!("public key must be an ssh-ed25519 key");
    };
    let blob = standard_base64(encoded)
        .map_err(|_| anyhow::anyhow!("public key is not valid OpenSSH base64"))?;
    let Some((kind, rest)) = ssh_string(&blob) else {
        bail!("public key contains an invalid key type");
    };
    if kind != b"ssh-ed25519" {
        bail!("public key contains an invalid key type");
    }
    let Some((key, rest)) = ssh_string(rest) else {
        bail!("public key contains invalid Ed25519 key data");
    };
    if key.len() != 32 || !rest.is_empty() {
        bail!("public key contains invalid Ed25519 key data");
    }
    let bytes = key.try_into().expect("checked key length");
    Ok(PublicKey {
        canonical: format!(
            "ssh-ed25519 {}",
            base64::engine::general_purpose::STANDARD.encode(&blob)
        ),
        bytes,
        fingerprint: format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(&blob))),
    })
}

pub fn parse_instance_key(value: &str) -> Result<([u8; 32], String)> {
    let bytes = standard_base64(value)
        .map_err(|_| anyhow::anyhow!("instance public key is not valid base64"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("instance public key must be 32 bytes"))?;
    let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes));
    Ok((bytes, id))
}

fn ssh_string(value: &[u8]) -> Option<(&[u8], &[u8])> {
    let (length, rest) = value.split_at_checked(4)?;
    let length = u32::from_be_bytes(length.try_into().ok()?) as usize;
    rest.split_at_checked(length)
}

pub struct RateLimiter {
    rate: f64,
    capacity: f64,
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    pub fn new(requests_per_minute: i64, burst: i64) -> Self {
        Self {
            rate: requests_per_minute as f64 / 60.,
            capacity: burst as f64,
            tokens: burst as f64,
            last: Instant::now(),
        }
    }

    pub fn allow(&mut self) -> bool {
        self.allow_at(Instant::now())
    }

    fn allow_at(&mut self, now: Instant) -> bool {
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.rate)
            .min(self.capacity);
        self.last = now;
        if self.tokens < 1. {
            return false;
        }
        self.tokens -= 1.;
        true
    }
}
