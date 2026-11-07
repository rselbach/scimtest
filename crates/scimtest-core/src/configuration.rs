use std::collections::{BTreeMap, HashSet};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::Error;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClaimMappings {
    pub name: String,
    pub given_name: String,
    pub family_name: String,
    pub username: String,
    pub email: String,
    pub groups: String,
}

impl Default for ClaimMappings {
    fn default() -> Self {
        Self {
            name: "name".into(),
            given_name: "given_name".into(),
            family_name: "family_name".into(),
            username: "preferred_username".into(),
            email: "email".into(),
            groups: "groups".into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default = "AttributeMappings::empty", deny_unknown_fields)]
pub struct AttributeMappings {
    pub given_name: String,
    pub family_name: String,
    pub username: String,
    pub email: String,
    pub groups: String,
}

impl AttributeMappings {
    fn empty() -> Self {
        Self {
            given_name: String::new(),
            family_name: String::new(),
            username: String::new(),
            email: String::new(),
            groups: String::new(),
        }
    }
}

pub const SAML_EMAIL_ATTRIBUTE: &str =
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";

impl Default for AttributeMappings {
    fn default() -> Self {
        Self {
            given_name: "firstName".into(),
            family_name: "lastName".into(),
            username: "username".into(),
            email: SAML_EMAIL_ATTRIBUTE.into(),
            groups: "groups".into(),
        }
    }
}

macro_rules! settings {
    ($($(#[$attribute:meta])* $name:ident: $ty:ty = $default:expr),+ $(,)?) => {
        #[derive(Clone, Debug, Deserialize, Serialize)]
        #[serde(default)]
        pub struct EnvironmentSettings {
            pub protocol: String,
            #[serde(skip_serializing_if = "String::is_empty")]
            pub saml_name_id_format: String,
            #[serde(skip_serializing_if = "std::ops::Not::not")]
            pub scim_capabilities_known: bool,
            #[serde(skip_serializing_if = "std::ops::Not::not")]
            pub scim_patch_supported: bool,
            #[serde(skip_serializing_if = "std::ops::Not::not")]
            pub scim_filter_supported: bool,
            $($(#[$attribute])* pub $name: $ty,)+
        }
        impl Default for EnvironmentSettings {
            fn default() -> Self { Self { protocol: "none".into(), saml_name_id_format: String::new(), scim_capabilities_known: false, scim_patch_supported: false, scim_filter_supported: false, $($name: $default,)+ } }
        }
        #[derive(Clone, Debug, Default, Deserialize, Serialize)]
        #[serde(default, deny_unknown_fields)]
        pub struct SettingsPatch {
            pub oidc_enabled: Option<bool>,
            pub saml_enabled: Option<bool>,
            pub regenerate_oidc_secret: Option<bool>,
            $(pub $name: Option<$ty>,)+
        }
        impl SettingsPatch {
            pub const FIELDS: &'static [&'static str] = &["oidc_enabled", "saml_enabled", "regenerate_oidc_secret", $(stringify!($name),)+];
        }
        impl EnvironmentSettings {
            pub(crate) fn storage_fields(&self) -> Result<serde_json::Map<String, serde_json::Value>, Error> {
                let mut fields = serde_json::Map::new();
                fields.insert("protocol".into(), serde_json::json!(self.protocol));
                fields.insert("saml_name_id_format".into(), serde_json::json!(self.saml_name_id_format));
                fields.insert("scim_capabilities_known".into(), serde_json::json!(self.scim_capabilities_known));
                fields.insert("scim_patch_supported".into(), serde_json::json!(self.scim_patch_supported));
                fields.insert("scim_filter_supported".into(), serde_json::json!(self.scim_filter_supported));
                $(fields.insert(stringify!($name).into(), serde_json::to_value(&self.$name)?);)+
                Ok(fields)
            }
            pub fn apply(&mut self, patch: SettingsPatch, slug: &str) -> Result<(), Error> {
                let oidc = patch.oidc_enabled.unwrap_or_else(|| self.supports_oidc());
                let saml = patch.saml_enabled.unwrap_or_else(|| self.supports_saml());
                let scim = patch.scim_enabled.unwrap_or(self.has_scim_setup());
                let previous_secret = self.oidc_client_secret.clone();
                let mappings_supplied = patch.saml_attribute_mappings.is_some();
                $(if let Some(value) = patch.$name { self.$name = value; })+
                if !mappings_supplied { self.saml_attribute_mappings.email = self.saml_email_attribute_name.clone(); }
                else { self.saml_email_attribute_name = self.saml_attribute_mappings.email.clone(); }
                if self.oidc_client_secret.trim().is_empty() { self.oidc_client_secret = previous_secret; }
                if patch.regenerate_oidc_secret == Some(true) { self.oidc_client_secret.clear(); }
                self.normalize(oidc, saml, scim, slug)
            }
        }
    };
}

settings! {
    #[serde(skip_serializing_if = "String::is_empty")]
    oidc_client_id: String = String::new(),
    #[serde(skip_serializing_if = "String::is_empty")]
    oidc_client_secret: String = String::new(),
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    oidc_public_client: bool = false,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    oidc_redirect_uris: Vec<String> = Vec::new(),
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    allow_any_oidc_redirect: bool = false,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    oidc_jwt_access_tokens: bool = false,
    #[serde(skip_serializing_if = "String::is_empty")]
    oidc_access_token_audience: String = String::new(),
    #[serde(skip_serializing_if = "String::is_empty")]
    oidc_backchannel_logout_uri: String = String::new(),
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    oidc_backchannel_logout_session_required: bool = false,
    #[serde(skip_serializing_if = "String::is_empty")]
    saml_entity_id: String = String::new(),
    #[serde(skip_serializing_if = "String::is_empty")]
    saml_acs_url: String = String::new(),
    #[serde(skip_serializing_if = "String::is_empty")]
    saml_slo_url: String = String::new(),
    #[serde(skip_serializing_if = "String::is_empty")]
    saml_audience: String = String::new(),
    #[serde(skip_serializing_if = "String::is_empty")]
    saml_name_id_field: String = "email".into(),
    #[serde(skip_serializing_if = "String::is_empty")]
    saml_email_attribute_name: String = SAML_EMAIL_ATTRIBUTE.into(),
    #[serde(skip_serializing_if = "String::is_empty")]
    saml_request_certificate_pem: String = String::new(),
    #[serde(skip_serializing_if = "String::is_empty")]
    saml_encryption_certificate_pem: String = String::new(),
    #[serde(skip_serializing_if = "String::is_empty")]
    saml_encryption_algorithm: String = "aes256-gcm".into(),
    #[serde(skip_serializing_if = "String::is_empty")]
    saml_signing_mode: String = "assertion".into(),
    include_groups_claim: bool = false,
    oidc_claim_mappings: ClaimMappings = ClaimMappings::default(),
    saml_attribute_mappings: AttributeMappings = AttributeMappings::default(),
    #[serde(skip_serializing_if = "String::is_empty")]
    chooser_mode: String = "list".into(),
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    scim_enabled: bool = false,
    #[serde(skip_serializing_if = "String::is_empty")]
    scim_base_url: String = String::new(),
    #[serde(skip_serializing_if = "String::is_empty")]
    scim_bearer_token: String = String::new(),
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    scim_auto_open_trace: bool = false,
    #[serde(skip_serializing_if = "String::is_empty")]
    persona: String = "generic".into(),
    #[serde(skip_serializing_if = "is_zero")]
    groups_overage_threshold: i64 = 0,
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

impl EnvironmentSettings {
    pub fn supports_oidc(&self) -> bool {
        matches!(self.protocol.as_str(), "oidc" | "both")
    }
    pub fn supports_saml(&self) -> bool {
        matches!(self.protocol.as_str(), "saml" | "both")
    }

    fn has_scim_setup(&self) -> bool {
        self.scim_enabled
            || !self.scim_base_url.trim().is_empty()
            || !self.scim_bearer_token.trim().is_empty()
    }

    fn normalize(&mut self, oidc: bool, saml: bool, scim: bool, slug: &str) -> Result<(), Error> {
        for value in [
            &mut self.oidc_client_id,
            &mut self.oidc_client_secret,
            &mut self.oidc_access_token_audience,
            &mut self.oidc_backchannel_logout_uri,
            &mut self.saml_entity_id,
            &mut self.saml_acs_url,
            &mut self.saml_slo_url,
            &mut self.saml_audience,
            &mut self.saml_request_certificate_pem,
            &mut self.saml_encryption_certificate_pem,
            &mut self.scim_base_url,
            &mut self.scim_bearer_token,
            &mut self.persona,
        ] {
            *value = value.trim().to_owned();
        }
        self.oidc_redirect_uris = self
            .oidc_redirect_uris
            .iter()
            .flat_map(|uri| uri.lines())
            .map(str::trim)
            .filter(|uri| !uri.is_empty())
            .map(str::to_owned)
            .collect();
        if !oidc {
            self.oidc_client_id.clear();
            self.oidc_client_secret.clear();
            self.oidc_redirect_uris.clear();
            self.oidc_public_client = false;
            self.allow_any_oidc_redirect = false;
            self.oidc_jwt_access_tokens = false;
            self.oidc_access_token_audience.clear();
            self.oidc_backchannel_logout_uri.clear();
            self.oidc_backchannel_logout_session_required = false;
        }
        if !saml {
            self.saml_entity_id.clear();
            self.saml_acs_url.clear();
            self.saml_slo_url.clear();
            self.saml_audience.clear();
            self.saml_request_certificate_pem.clear();
            self.saml_encryption_certificate_pem.clear();
            self.saml_encryption_algorithm.clear();
            self.saml_signing_mode.clear();
        }
        if !scim {
            self.scim_base_url.clear();
            self.scim_bearer_token.clear();
            self.scim_auto_open_trace = false;
            self.scim_capabilities_known = false;
            self.scim_patch_supported = false;
            self.scim_filter_supported = false;
        }
        let oidc = oidc
            && (self.supports_oidc()
                || !self.oidc_client_id.is_empty()
                || !self.oidc_client_secret.is_empty()
                || !self.oidc_redirect_uris.is_empty()
                || self.oidc_public_client
                || self.allow_any_oidc_redirect);
        let saml = saml
            && (self.supports_saml()
                || !self.saml_entity_id.is_empty()
                || !self.saml_acs_url.is_empty()
                || !self.saml_audience.is_empty());
        if oidc {
            if self.oidc_client_id.is_empty() {
                self.oidc_client_id = slug.into();
            }
            if self.oidc_public_client {
                self.oidc_client_secret.clear();
            } else if self.oidc_client_secret.is_empty() {
                self.oidc_client_secret = random_secret(24);
            }
        }
        self.scim_enabled =
            scim && !self.scim_base_url.is_empty() && !self.scim_bearer_token.is_empty();
        self.protocol = match (oidc, saml) {
            (true, true) => "both",
            (true, false) => "oidc",
            (false, true) => "saml",
            _ if self.has_scim_setup() => "scim",
            _ => "none",
        }
        .into();
        self.chooser_mode = if self.chooser_mode.trim() == "identifier" {
            "identifier"
        } else {
            "list"
        }
        .into();
        if self.persona.is_empty() {
            self.persona = "generic".into();
        }
        self.saml_name_id_field = match self.saml_name_id_field.trim() {
            "username" => "username",
            "firstName" => "firstName",
            "lastName" => "lastName",
            _ => "email",
        }
        .into();
        if saml {
            self.saml_name_id_format = if self.saml_name_id_field == "email" {
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
            } else {
                "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
            }
            .into();
        }
        if saml {
            self.saml_encryption_algorithm =
                defaulted(&self.saml_encryption_algorithm, "aes256-gcm");
            self.saml_signing_mode = defaulted(&self.saml_signing_mode, "assertion");
        }
        self.fill_mappings();
        self.saml_email_attribute_name
            .clone_from(&self.saml_attribute_mappings.email);
        self.validate()
    }

    fn fill_mappings(&mut self) {
        if self.saml_attribute_mappings.email.trim().is_empty() {
            self.saml_attribute_mappings
                .email
                .clone_from(&self.saml_email_attribute_name);
        }
        let defaults = ClaimMappings::default();
        for (value, fallback) in [
            (&mut self.oidc_claim_mappings.name, defaults.name),
            (
                &mut self.oidc_claim_mappings.given_name,
                defaults.given_name,
            ),
            (
                &mut self.oidc_claim_mappings.family_name,
                defaults.family_name,
            ),
            (&mut self.oidc_claim_mappings.username, defaults.username),
            (&mut self.oidc_claim_mappings.email, defaults.email),
            (&mut self.oidc_claim_mappings.groups, defaults.groups),
        ] {
            *value = defaulted(value, &fallback);
        }
        let defaults = AttributeMappings::default();
        for (value, fallback) in [
            (
                &mut self.saml_attribute_mappings.given_name,
                defaults.given_name,
            ),
            (
                &mut self.saml_attribute_mappings.family_name,
                defaults.family_name,
            ),
            (
                &mut self.saml_attribute_mappings.username,
                defaults.username,
            ),
            (&mut self.saml_attribute_mappings.email, defaults.email),
            (&mut self.saml_attribute_mappings.groups, defaults.groups),
        ] {
            *value = defaulted(value, &fallback);
        }
    }

    pub(crate) fn normalize_loaded(&mut self, slug: &str) {
        if self.protocol.is_empty() {
            self.protocol = "oidc".into();
        }
        if self.supports_oidc() && self.oidc_client_id.is_empty() {
            self.oidc_client_id = slug.into();
        }
        if self.supports_saml() {
            self.saml_name_id_field = match self.saml_name_id_field.trim() {
                "username" => "username",
                "firstName" => "firstName",
                "lastName" => "lastName",
                _ => "email",
            }
            .into();
            self.saml_name_id_format = if self.saml_name_id_field == "email" {
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
            } else {
                "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
            }
            .into();
            if self.saml_email_attribute_name.is_empty() {
                self.saml_email_attribute_name = SAML_EMAIL_ATTRIBUTE.into();
            }
        }
        let saml = self.supports_saml()
            || [
                &self.saml_entity_id,
                &self.saml_acs_url,
                &self.saml_audience,
            ]
            .iter()
            .any(|value| !value.trim().is_empty());
        if !self.saml_encryption_algorithm.is_empty()
            || saml
            || !self.saml_encryption_certificate_pem.trim().is_empty()
        {
            self.saml_encryption_algorithm =
                defaulted(&self.saml_encryption_algorithm, "aes256-gcm");
        }
        if !self.saml_signing_mode.is_empty() || saml {
            self.saml_signing_mode = defaulted(&self.saml_signing_mode, "assertion");
        }
        self.fill_mappings();
        if self.supports_saml() {
            self.saml_email_attribute_name
                .clone_from(&self.saml_attribute_mappings.email);
        }
        self.chooser_mode = if self.chooser_mode.trim() == "identifier" {
            "identifier"
        } else {
            "list"
        }
        .into();
        self.persona = match self.persona.trim() {
            "entra" => "entra",
            "okta" => "okta",
            "google" => "google",
            _ => "generic",
        }
        .into();
        self.oidc_redirect_uris = self
            .oidc_redirect_uris
            .iter()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .collect();
        self.scim_base_url = self.scim_base_url.trim().trim_end_matches('/').into();
        if !self.scim_enabled
            && !self.scim_base_url.is_empty()
            && !self.scim_bearer_token.trim().is_empty()
            && validate_http_url("SCIM base URL", &self.scim_base_url, true).is_ok()
        {
            self.scim_enabled = true;
        }
        let oidc = self.supports_oidc()
            || !self.oidc_client_id.trim().is_empty()
            || !self.oidc_client_secret.trim().is_empty()
            || !self.oidc_redirect_uris.is_empty()
            || self.oidc_public_client
            || self.allow_any_oidc_redirect;
        self.protocol = match (oidc, saml) {
            (true, true) => "both",
            (true, false) => "oidc",
            (false, true) => "saml",
            _ if self.has_scim_setup() => "scim",
            _ => "none",
        }
        .into();
    }

    pub fn validate(&self) -> Result<(), Error> {
        validate_http_url("SCIM base URL", &self.scim_base_url, false)?;
        if self.supports_oidc() {
            for value in &self.oidc_redirect_uris {
                validate_endpoint("OIDC redirect URI", value)?;
            }
            if !self.oidc_backchannel_logout_uri.is_empty() {
                validate_endpoint("Back-channel logout URI", &self.oidc_backchannel_logout_uri)?;
            }
            validate_mappings(
                "OIDC claim",
                &[
                    &self.oidc_claim_mappings.name,
                    &self.oidc_claim_mappings.given_name,
                    &self.oidc_claim_mappings.family_name,
                    &self.oidc_claim_mappings.username,
                    &self.oidc_claim_mappings.email,
                    &self.oidc_claim_mappings.groups,
                ],
                &["iss", "sub", "aud", "exp", "iat", "nonce", "email_verified"],
            )?;
        }
        if self.supports_saml() {
            for (label, value) in [
                ("SAML ACS URL", &self.saml_acs_url),
                ("SAML Single Logout URL", &self.saml_slo_url),
            ] {
                if !value.is_empty() {
                    validate_endpoint(label, value)?;
                }
            }
            validate_mappings(
                "SAML attribute",
                &[
                    &self.saml_attribute_mappings.given_name,
                    &self.saml_attribute_mappings.family_name,
                    &self.saml_attribute_mappings.username,
                    &self.saml_attribute_mappings.email,
                    &self.saml_attribute_mappings.groups,
                ],
                &[],
            )?;
            validate_certificate(
                "SAML request-signing certificate",
                &self.saml_request_certificate_pem,
            )?;
            validate_certificate(
                "SAML encryption certificate",
                &self.saml_encryption_certificate_pem,
            )?;
        }
        if !["generic", "entra", "okta", "google"].contains(&self.persona.as_str()) {
            return Err(Error::Validation(
                "persona must be generic, entra, okta, or google".into(),
            ));
        }
        if !["assertion", "response", "both"]
            .contains(&defaulted(&self.saml_signing_mode, "assertion").as_str())
        {
            return Err(Error::Validation(
                "SAML signing mode must be assertion, response, or both".into(),
            ));
        }
        if !["aes128-gcm", "aes192-gcm", "aes256-gcm"]
            .contains(&defaulted(&self.saml_encryption_algorithm, "aes256-gcm").as_str())
        {
            return Err(Error::Validation(
                "SAML encryption algorithm must be AES-128-GCM, AES-192-GCM, or AES-256-GCM".into(),
            ));
        }
        if self.groups_overage_threshold < 0 {
            return Err(Error::Validation(
                "groups overage threshold must not be negative".into(),
            ));
        }
        Ok(())
    }
}

fn defaulted(value: &str, fallback: &str) -> String {
    match value.trim() {
        "" => fallback,
        value => value,
    }
    .into()
}

fn validate_mappings(kind: &str, values: &[&String], reserved: &[&str]) -> Result<(), Error> {
    let mut names = HashSet::new();
    for value in values {
        let name = value.trim();
        if name.is_empty() {
            return Err(Error::Validation(format!("{kind} names are required")));
        }
        if reserved.contains(&name) {
            return Err(Error::Validation(format!(
                "{kind} name {name:?} is reserved"
            )));
        }
        if !names.insert(name) {
            return Err(Error::Validation(format!(
                "{kind} name {name:?} is configured more than once"
            )));
        }
    }
    Ok(())
}

fn validate_endpoint(label: &str, value: &str) -> Result<(), Error> {
    let uri = url::Url::parse(value).map_err(|_| {
        Error::Validation(format!(
            "{label} must be an absolute HTTP(S) URL without a fragment"
        ))
    })?;
    if !["http", "https"].contains(&uri.scheme())
        || uri.host_str().is_none()
        || uri.fragment().is_some()
    {
        return Err(Error::Validation(format!(
            "{label} must be an absolute HTTP(S) URL without a fragment"
        )));
    }
    Ok(())
}

fn validate_certificate(label: &str, value: &str) -> Result<(), Error> {
    use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};
    if value.trim().is_empty() {
        return Ok(());
    }
    let invalid = |message: &str| Error::Validation(format!("{label} is invalid: {message}"));
    let (rest, pem) = parse_x509_pem(value.trim().as_bytes())
        .map_err(|_| invalid("certificate PEM block is required"))?;
    if pem.label != "CERTIFICATE" || rest.iter().any(|byte| !byte.is_ascii_whitespace()) {
        return Err(invalid("only one CERTIFICATE PEM block is supported"));
    }
    let (rest, certificate) =
        parse_x509_certificate(&pem.contents).map_err(|_| invalid("invalid X.509 certificate"))?;
    if !rest.is_empty() {
        return Err(invalid("invalid X.509 certificate"));
    }
    if certificate
        .public_key()
        .parsed()
        .ok()
        .is_none_or(|key| !matches!(key, x509_parser::public_key::PublicKey::RSA(_)))
    {
        return Err(invalid("certificate public key must be RSA"));
    }
    if !certificate.validity().is_valid() {
        return Err(invalid("certificate is not currently valid"));
    }
    Ok(())
}

pub fn random_secret(bytes: usize) -> String {
    let mut value = vec![0; bytes];
    rand::rngs::OsRng.fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

pub fn validate_http_url(label: &str, value: &str, required: bool) -> Result<(), Error> {
    if value.trim().is_empty() && !required {
        return Ok(());
    }
    let url = url::Url::parse(value)
        .map_err(|_| Error::Validation(format!("{label} must be an absolute HTTP(S) URL")))?;
    if !["http", "https"].contains(&url.scheme())
        || url.host_str().is_none()
        || url.query().is_some_and(|query| !query.is_empty())
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(Error::Validation(format!(
            "{label} must be an absolute HTTP(S) URL without credentials or a fragment"
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GlobalConfig {
    pub idp_base_url: String,
    pub trust_forwarded_headers: bool,
    pub debug: bool,
    pub record_traffic: bool,
    pub record_secrets: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GlobalConfigPatch {
    pub idp_base_url: Option<String>,
    pub trust_forwarded_headers: Option<bool>,
    pub debug: Option<bool>,
    pub record_traffic: Option<bool>,
    pub record_secrets: Option<bool>,
}

impl crate::Store {
    pub fn global_config(&self) -> Result<GlobalConfig, Error> {
        let connection = self.connection()?;
        let values = crate::persistence::config_values(&connection, None)?;
        Ok(GlobalConfig {
            idp_base_url: values
                .get("idp_base_url")
                .cloned()
                .unwrap_or_default()
                .trim_end_matches('/')
                .into(),
            trust_forwarded_headers: values
                .get("trust_forwarded_headers")
                .is_some_and(|value| value == "1"),
            ..Default::default()
        })
    }

    pub fn update_global_config(&self, patch: &GlobalConfigPatch) -> Result<(), Error> {
        let _mutation = self.mutation()?;
        if let Some(value) = &patch.idp_base_url {
            validate_http_url("IDP base URL", value, false)?;
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        if let Some(value) = &patch.idp_base_url {
            transaction.execute("INSERT INTO config VALUES ('idp_base_url', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value", [value.trim().trim_end_matches('/')])?;
        }
        if let Some(value) = patch.trust_forwarded_headers {
            transaction.execute("INSERT INTO config VALUES ('trust_forwarded_headers', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value", [if value { "1" } else { "0" }])?;
        }
        transaction.commit()?;
        self.changed();
        Ok(())
    }
}

pub type ConfigValues = BTreeMap<String, String>;
