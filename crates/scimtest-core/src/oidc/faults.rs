use super::*;
use crate::duration::{format as format_duration, parse as parse_duration};
use crate::signing::SigningKey;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Faults {
    pub id_token_ttl: Option<String>,
    pub assertion_ttl: Option<String>,
    pub saml_status: String,
    pub clock_skew: Option<String>,
    pub break_signature: bool,
    pub drop_claims: Vec<String>,
    pub token_error: String,
    pub tamper: Vec<String>,
}
impl Faults {
    pub fn validate(&self) -> std::result::Result<(), Error> {
        self.clone().normalized().map(|_| ())
    }
    pub fn normalized(mut self) -> std::result::Result<Self, Error> {
        for value in [
            &mut self.id_token_ttl,
            &mut self.assertion_ttl,
            &mut self.clock_skew,
        ] {
            *value = value
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| {
                    let nanos = parse_duration(value)
                        .ok_or_else(|| Error::Validation(format!("invalid duration {value:?}")))?;
                    Ok::<_, Error>(format_duration(nanos))
                })
                .transpose()?;
        }
        self.saml_status = self.saml_status.trim().to_owned();
        if !self.saml_status.is_empty() && self.saml_status_value().is_none() {
            return Err(Error::Validation(
                "saml_status must be Responder or AuthnFailed".into(),
            ));
        }
        if self.saml_status.eq_ignore_ascii_case("responder") {
            self.saml_status = "Responder".into();
        }
        if self.saml_status.eq_ignore_ascii_case("authnfailed") {
            self.saml_status = "AuthnFailed".into();
        }
        self.token_error = self.token_error.trim().to_owned();
        self.drop_claims = comma_values(&self.drop_claims);
        let mut tamper = Vec::new();
        for name in comma_values(&self.tamper) {
            if !tamper.contains(&name) {
                tamper.push(name);
            }
        }
        self.tamper = tamper;
        for fault in &self.tamper {
            if !TAMPER_FAULTS.contains(&fault.as_str()) {
                return Err(Error::Validation(format!(
                    "ignored unknown fault_tamper {fault:?}"
                )));
            }
        }
        Ok(self)
    }
    pub fn active(&self) -> bool {
        self.id_token_ttl.is_some()
            || self.assertion_ttl.is_some()
            || !self.saml_status.is_empty()
            || !self.skew().is_zero()
            || self.break_signature
            || !self.drop_claims.is_empty()
            || !self.token_error.is_empty()
            || !self.tamper.is_empty()
    }
    pub(crate) fn from_parameters(values: &Parameters) -> Self {
        let valid_duration = |name| {
            let value = param(values, name).trim();
            parse_duration(value).map(format_duration)
        };
        let mut faults = Self {
            id_token_ttl: valid_duration("fault_id_token_ttl"),
            assertion_ttl: valid_duration("fault_assertion_ttl"),
            saml_status: param(values, "fault_saml_status").trim().into(),
            clock_skew: valid_duration("fault_clock_skew"),
            break_signature: truthy(param(values, "fault_break_signature")),
            drop_claims: param(values, "fault_drop_claims")
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect(),
            token_error: param(values, "fault_token_error").trim().into(),
            tamper: param(values, "fault_tamper")
                .split(',')
                .map(str::trim)
                .filter(|name| TAMPER_FAULTS.contains(name) && !name.starts_with("logout_"))
                .map(str::to_owned)
                .collect(),
        };
        if !faults.saml_status.is_empty() && faults.saml_status_value().is_none() {
            eprintln!(
                "Ignoring invalid SAML status fault {:?}",
                faults.saml_status
            );
            faults.saml_status.clear();
        }
        if let Ok(normalized) = faults.clone().normalized() {
            return normalized;
        }
        faults
    }
    pub(crate) fn tampers(&self, value: &str) -> bool {
        self.tamper.iter().any(|name| name == value)
    }
    pub(crate) fn skew(&self) -> Duration {
        self.clock_skew
            .as_deref()
            .and_then(duration)
            .unwrap_or_default()
    }
    pub(super) fn drop(&self, claims: &mut Value) {
        if let Some(object) = claims.as_object_mut() {
            for name in &self.drop_claims {
                object.remove(name);
            }
        }
    }
    pub(super) fn apply(&self, claims: &mut Value, now: DateTime<Utc>) {
        self.drop(claims);
        self.tamper_claims(claims);
        if self.tampers("nonce_mismatch") {
            claims["nonce"] = json!(near_miss(&claims["nonce"]));
        }
        let issued = now + self.skew();
        if !self.skew().is_zero() {
            claims["iat"] = json!(issued.timestamp());
        }
        claims["exp"] = json!(
            (issued
                + self
                    .id_token_ttl
                    .as_deref()
                    .and_then(duration)
                    .unwrap_or(Duration::hours(1)))
            .timestamp()
        );
    }
    pub(super) fn tamper_claims(&self, claims: &mut Value) {
        if self.tampers("wrong_issuer") {
            claims["iss"] = json!(near_miss(&claims["iss"]));
        }
        if self.tampers("wrong_audience") {
            claims["aud"] = json!(near_miss(&claims["aud"]));
        }
    }
    pub(super) fn sign(
        &self,
        key: &SigningKey,
        claims: &Value,
        typ: &str,
    ) -> std::result::Result<String, Error> {
        if self.tampers("alg_none") {
            return Ok(format!(
                "{}.{}.",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"typ":typ,"alg":"none"}))?),
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?)
            ));
        }
        let kid = if self.tampers("unknown_kid") {
            "scimtest-unknown"
        } else {
            &key.stored.kid
        };
        let mut token =
            key.sign_jwt_with_header(claims, &json!({"alg":"RS256","typ":typ,"kid":kid}))?;
        if self.break_signature
            && let Some(index) = token.rfind('.')
        {
            let replacement = if token.as_bytes()[index + 1] == b'A' {
                "B"
            } else {
                "A"
            };
            token.replace_range(index + 1..index + 2, replacement);
        }
        Ok(token)
    }
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ttl) = &self.id_token_ttl {
            parts.push(format!("ID token TTL {ttl}"));
        }
        if let Some(ttl) = &self.assertion_ttl {
            parts.push(format!("assertion TTL {ttl}"));
        }
        if !self.saml_status.is_empty() {
            parts.push(format!("SAML status {}", self.saml_status));
        }
        if let Some(skew) = &self.clock_skew
            && !self.skew().is_zero()
        {
            parts.push(format!("clock skew {skew}"));
        }
        if self.break_signature {
            parts.push("broken signature".into());
        }
        if !self.drop_claims.is_empty() {
            parts.push(format!("dropped claims {}", self.drop_claims.join(",")));
        }
        if !self.token_error.is_empty() {
            parts.push(format!("token error {}", self.token_error));
        }
        if !self.tamper.is_empty() {
            parts.push(format!("tamper {}", self.tamper.join(",")));
        }
        parts.join("; ")
    }
}
impl Faults {
    pub(crate) fn saml_status_value(&self) -> Option<&'static str> {
        match self.saml_status.to_ascii_lowercase().as_str() {
            "responder" => Some("urn:oasis:names:tc:SAML:2.0:status:Responder"),
            "authnfailed" => Some("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"),
            _ => None,
        }
    }
}
fn comma_values(values: &[String]) -> Vec<String> {
    values
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}
const TAMPER_FAULTS: &[&str] = &[
    "wrong_issuer",
    "wrong_audience",
    "unknown_kid",
    "alg_none",
    "nonce_mismatch",
    "wrong_destination",
    "wrong_recipient",
    "in_response_to_mismatch",
    "replayed_assertion",
    "xsw_assertion",
    "xsw_response",
    "nameid_comment",
    "logout_alg_none",
    "logout_wrong_audience",
    "logout_missing_events",
    "logout_repeated_jti",
];

fn near_miss(value: &Value) -> String {
    value
        .as_str()
        .filter(|value| !value.is_empty())
        .map(|value| format!("{value}-wrong"))
        .unwrap_or_else(|| "scimtest-wrong".into())
}
pub(crate) fn duration(value: &str) -> Option<Duration> {
    parse_duration(value).map(Duration::nanoseconds)
}
