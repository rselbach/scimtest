use super::*;
use crate::{oidc::Parameters, signing::SigningKey};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Duration, Utc};
use std::io::Write;

pub const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const STATUS_REQUESTER: &str = "urn:oasis:names:tc:SAML:2.0:status:Requester";
const STATUS_UNKNOWN: &str = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal";

#[derive(Clone, Debug)]
pub struct LogoutStatus {
    pub code: String,
    pub subcode: String,
    pub message: String,
}
impl LogoutStatus {
    pub fn success() -> Self {
        Self {
            code: STATUS_SUCCESS.into(),
            subcode: String::new(),
            message: String::new(),
        }
    }
    pub fn requester(message: impl Into<String>) -> Self {
        Self {
            code: STATUS_REQUESTER.into(),
            subcode: String::new(),
            message: message.into(),
        }
    }
    pub fn unknown(message: impl Into<String>) -> Self {
        Self {
            subcode: STATUS_UNKNOWN.into(),
            ..Self::requester(message)
        }
    }
    pub fn is_success(&self) -> bool {
        self.code == STATUS_SUCCESS
    }
    fn xml(&self) -> String {
        let subcode = if self.subcode.is_empty() {
            "/>".into()
        } else {
            format!(
                "><samlp:StatusCode Value=\"{}\"/></samlp:StatusCode>",
                xml_escape(&self.subcode)
            )
        };
        let message = if self.message.is_empty() {
            String::new()
        } else {
            format!(
                "<samlp:StatusMessage>{}</samlp:StatusMessage>",
                xml_escape(&self.message)
            )
        };
        format!(
            "<samlp:Status><samlp:StatusCode Value=\"{}\"{subcode}{message}</samlp:Status>",
            xml_escape(&self.code)
        )
    }
}
impl std::fmt::Display for LogoutStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code.rsplit(':').next().unwrap_or_default())?;
        if !self.subcode.is_empty() {
            write!(
                f,
                "/{}",
                self.subcode.rsplit(':').next().unwrap_or_default()
            )?;
        }
        if !self.message.is_empty() {
            write!(f, ": {}", self.message)?;
        }
        Ok(())
    }
}

pub struct LogoutMessage {
    pub xml: String,
    pub response: bool,
    pub binding: &'static str,
    pub relay_state: String,
    pub id: String,
    pub in_response_to: String,
    pub name_id: String,
    pub name_id_format: String,
    pub session_indexes: Vec<String>,
    issuer: String,
    destination: String,
    issued: String,
    expiry: String,
    status: Option<LogoutStatus>,
}
impl LogoutMessage {
    pub fn verify_sender(
        &self,
        environment: &crate::model::Environment,
        query: &str,
    ) -> Result<bool, Error> {
        let kind = if self.response {
            "LogoutResponse"
        } else {
            "LogoutRequest"
        };
        if self.issuer.is_empty() {
            return Err(Error::Validation(format!("SAML {kind} Issuer is required")));
        }
        let settings = &environment.settings;
        if !settings.saml_entity_id.trim().is_empty()
            && self.issuer != settings.saml_entity_id.trim()
        {
            return Err(Error::Validation(format!(
                "SAML {kind} issuer does not match the configured app"
            )));
        }
        if settings.saml_request_certificate_pem.is_empty() {
            return Ok(false);
        }
        if self.binding == REDIRECT_BINDING {
            verify_redirect(
                query,
                if self.response {
                    "SAMLResponse"
                } else {
                    "SAMLRequest"
                },
                kind,
                &settings.saml_request_certificate_pem,
            )?;
        } else {
            verify_xml(&self.xml, &settings.saml_request_certificate_pem, kind)?;
        }
        Ok(true)
    }
    pub fn check(&self, destination: &str, signed: bool, now: DateTime<Utc>) -> Result<(), Error> {
        if self.destination.is_empty() && signed {
            return Err(Error::Validation(format!(
                "signed SAML logout message must carry Destination {destination}"
            )));
        }
        if !self.destination.is_empty() && self.destination != destination {
            return Err(Error::Validation(format!(
                "SAML logout destination does not match {destination}"
            )));
        }
        let skew = Duration::minutes(3);
        let issued = DateTime::parse_from_rfc3339(&self.issued).map_err(|_| {
            Error::Validation("SAML logout IssueInstant must be an xs:dateTime".into())
        })?;
        if issued > now + skew {
            return Err(Error::Validation(
                "SAML logout IssueInstant is in the future".into(),
            ));
        }
        if issued < now - Duration::minutes(5) - skew {
            return Err(Error::Validation(
                "SAML logout IssueInstant is more than 5m old".into(),
            ));
        }
        if !self.expiry.is_empty() {
            let expiry = DateTime::parse_from_rfc3339(&self.expiry).map_err(|_| {
                Error::Validation("SAML logout NotOnOrAfter must be an xs:dateTime".into())
            })?;
            if now >= expiry + skew {
                return Err(Error::Validation("SAML logout message expired".into()));
            }
        }
        Ok(())
    }
    pub fn status(&self) -> Result<&LogoutStatus, Error> {
        self.status
            .as_ref()
            .ok_or_else(|| Error::Validation("SAML LogoutResponse has no StatusCode".into()))
    }
}
pub fn read_logout(values: &Parameters, post: bool) -> Result<LogoutMessage, Error> {
    let value = |name: &str| values.get(name).map(String::as_str).unwrap_or_default();
    let request = value("SAMLRequest");
    let response = value("SAMLResponse");
    if !request.is_empty() && !response.is_empty() {
        return Err(Error::Validation(
            "send either SAMLRequest or SAMLResponse, not both".into(),
        ));
    }
    if request.is_empty() && response.is_empty() {
        return Err(Error::Validation(
            "SAMLRequest or SAMLResponse is required".into(),
        ));
    }
    let response = !response.is_empty();
    let xml = decode_message(if response {
        value("SAMLResponse")
    } else {
        request
    })?;
    let document = bergshamra::xml::uppsala::parse(&xml).map_err(crypto_error)?;
    let root = document
        .document_element()
        .ok_or_else(|| Error::Validation("SAML root is required".into()))?;
    let kind = if response {
        "LogoutResponse"
    } else {
        "LogoutRequest"
    };
    if !crypto::named(&document, root, PROTOCOL_NS, kind) {
        return Err(Error::Validation(format!(
            "SAML message must contain a {kind}"
        )));
    }
    let attribute = |name| {
        document
            .get_attribute(root, name)
            .unwrap_or_default()
            .trim()
            .to_owned()
    };
    let id = attribute("ID");
    if !response && id.is_empty() {
        return Err(Error::Validation(
            "SAML LogoutRequest ID is required".into(),
        ));
    }
    let text = |namespace, name| {
        crypto::child(&document, root, namespace, name)
            .map(|node| document.text_content_deep(node).trim().to_owned())
            .unwrap_or_default()
    };
    let name_id = text(ASSERTION_NS, "NameID");
    if !response {
        if ["EncryptedID", "BaseID"]
            .iter()
            .any(|name| crypto::child(&document, root, ASSERTION_NS, name).is_some())
        {
            return Err(Error::Validation(
                "SAML LogoutRequest requires the plaintext NameID from the assertion".into(),
            ));
        }
        if name_id.is_empty() {
            return Err(Error::Validation(
                "SAML LogoutRequest NameID is required".into(),
            ));
        }
    }
    let name_id_format = crypto::child(&document, root, ASSERTION_NS, "NameID")
        .and_then(|node| document.get_attribute(node, "Format"))
        .unwrap_or_default()
        .trim()
        .to_owned();
    let session_indexes = document
        .children(root)
        .into_iter()
        .filter(|node| crypto::named(&document, *node, PROTOCOL_NS, "SessionIndex"))
        .map(|node| document.text_content_deep(node).trim().to_owned())
        .collect();
    let status = crypto::child(&document, root, PROTOCOL_NS, "Status").and_then(|status| {
        let code = crypto::child(&document, status, PROTOCOL_NS, "StatusCode")?;
        let value = document.get_attribute(code, "Value")?.trim();
        if value.is_empty() {
            return None;
        }
        Some(LogoutStatus {
            code: value.into(),
            subcode: crypto::child(&document, code, PROTOCOL_NS, "StatusCode")
                .and_then(|node| document.get_attribute(node, "Value"))
                .unwrap_or_default()
                .trim()
                .into(),
            message: crypto::child(&document, status, PROTOCOL_NS, "StatusMessage")
                .map(|node| document.text_content_deep(node).trim().to_owned())
                .unwrap_or_default(),
        })
    });
    let message = LogoutMessage {
        response,
        binding: if post { POST_BINDING } else { REDIRECT_BINDING },
        relay_state: value("RelayState").into(),
        id,
        in_response_to: attribute("InResponseTo"),
        name_id,
        name_id_format,
        session_indexes,
        issuer: text(ASSERTION_NS, "Issuer"),
        destination: attribute("Destination"),
        issued: attribute("IssueInstant"),
        expiry: attribute("NotOnOrAfter"),
        status,
        xml: xml.clone(),
    };
    Ok(message)
}

pub struct OutboundMessage {
    pub id: String,
    pub binding: &'static str,
    pub param: &'static str,
    pub destination: String,
    pub xml: String,
    pub relay_state: String,
    pub url: String,
    pub encoded: String,
}
impl OutboundMessage {
    pub fn binding_name(&self) -> &'static str {
        binding_name(self.binding)
    }
    pub fn api_response(&self) -> serde_json::Value {
        let mut response =
            serde_json::json!({"request_id":self.id,"binding":self.binding_name(),"url":self.url});
        if self.binding == POST_BINDING {
            response["url"] = serde_json::json!(self.destination);
            response["form"] = serde_json::json!({self.param:self.encoded});
        }
        response
    }
}
pub(crate) fn binding_name(binding: &str) -> &'static str {
    if binding == POST_BINDING {
        "HTTP-POST"
    } else {
        "HTTP-Redirect"
    }
}
pub fn parse_binding(value: &str) -> Result<&'static str, Error> {
    match value
        .trim()
        .to_ascii_lowercase()
        .trim_start_matches("http-")
    {
        "" | "redirect" => Ok(REDIRECT_BINDING),
        "post" => Ok(POST_BINDING),
        _ => Err(Error::Validation(format!(
            "binding must be redirect or post, not {value:?}"
        ))),
    }
}
pub fn build_logout_request(
    issuer: &str,
    destination: &str,
    name: &str,
    format: &str,
    index: &str,
    now: DateTime<Utc>,
) -> (String, String) {
    let id = crate::store::new_id("saml-logout-request");
    let format = response::optional_attribute("Format", format);
    let xml = format!(
        r#"<samlp:LogoutRequest xmlns:samlp="{PROTOCOL_NS}" xmlns:saml="{ASSERTION_NS}" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}" NotOnOrAfter="{}" Reason="urn:oasis:names:tc:SAML:2.0:logout:admin"><saml:Issuer>{}</saml:Issuer><saml:NameID{format}>{}</saml:NameID><samlp:SessionIndex>{}</samlp:SessionIndex></samlp:LogoutRequest>"#,
        xml_escape(&id),
        response::instant(now),
        xml_escape(destination),
        response::instant(now + Duration::minutes(5)),
        xml_escape(issuer),
        xml_escape(name),
        xml_escape(index)
    );
    (id, xml)
}
pub fn build_logout_response(
    issuer: &str,
    destination: &str,
    in_response_to: &str,
    status: &LogoutStatus,
    now: DateTime<Utc>,
) -> String {
    format!(
        r#"<samlp:LogoutResponse xmlns:samlp="{PROTOCOL_NS}" xmlns:saml="{ASSERTION_NS}" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}" InResponseTo="{}"><saml:Issuer>{}</saml:Issuer>{}</samlp:LogoutResponse>"#,
        crate::store::new_id("saml-logout-response"),
        response::instant(now),
        xml_escape(destination),
        xml_escape(in_response_to),
        xml_escape(issuer),
        status.xml()
    )
}
pub fn encode_logout(
    key: &SigningKey,
    binding: &'static str,
    param: &'static str,
    destination: &str,
    xml: String,
    relay: &str,
) -> Result<OutboundMessage, Error> {
    let mut message = OutboundMessage {
        id: String::new(),
        binding,
        param,
        destination: destination.into(),
        xml,
        relay_state: relay.into(),
        url: String::new(),
        encoded: String::new(),
    };
    if binding == POST_BINDING {
        message.xml = sign_xml(&message.xml, key)?;
        message.encoded = STANDARD.encode(&message.xml);
        return Ok(message);
    }
    let mut writer = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    writer
        .write_all(message.xml.as_bytes())
        .map_err(crypto_error)?;
    let encoded = STANDARD.encode(writer.finish().map_err(crypto_error)?);
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair(param, &encoded);
    if !relay.is_empty() {
        query.append_pair("RelayState", relay);
    }
    query.append_pair("SigAlg", RSA_SHA256);
    let mut query = query.finish();
    use rsa::Pkcs1v15Sign;
    use sha2::{Digest, Sha256};
    let signature = key
        .private
        .sign(
            Pkcs1v15Sign::new::<Sha256>(),
            &Sha256::digest(query.as_bytes()),
        )
        .map_err(crypto_error)?;
    let signature = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("Signature", &STANDARD.encode(&signature))
        .finish();
    query.push('&');
    query.push_str(&signature);
    let mut target = url::Url::parse(destination).map_err(crypto_error)?;
    if let Some(existing) = target.query().filter(|query| !query.is_empty()) {
        query = format!("{existing}&{query}");
    }
    target.set_query(Some(&query));
    message.url = target.into();
    Ok(message)
}
