use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::io::Read;

pub fn decode_message(value: &str) -> Result<String, Error> {
    let normalized = value.trim().replace(['\r', '\n'], "");
    let value = normalized.as_str();
    if value.is_empty() {
        return Err(Error::Validation("SAMLRequest is required".into()));
    }
    let decoded = STANDARD
        .decode(value)
        .or_else(|_| STANDARD.decode(value.replace(' ', "+")))
        .map_err(|error| Error::Validation(format!("decode SAMLRequest: {error}")))?;
    let mut inflated = Vec::new();
    let result = flate2::read::DeflateDecoder::new(decoded.as_slice())
        .take((1 << 20) + 1)
        .read_to_end(&mut inflated);
    if inflated.len() > 1 << 20 {
        return Err(Error::Validation(
            "inflated SAMLRequest exceeds 1048576 bytes".into(),
        ));
    }
    let bytes = if result.is_err() || inflated.is_empty() {
        decoded
    } else {
        inflated
    };
    if bytes.len() > 1 << 20 {
        return Err(Error::Validation(
            "inflated SAMLRequest exceeds 1048576 bytes".into(),
        ));
    }
    let xml = String::from_utf8(bytes)
        .map_err(|error| Error::Validation(format!("parse SAMLRequest XML: {error}")))?;
    bergshamra::xml::uppsala::parse(&xml)
        .map_err(|error| Error::Validation(format!("parse SAMLRequest XML: {error}")))?;
    Ok(xml)
}

#[derive(Clone, Debug, Default)]
pub struct AuthnRequest {
    pub id: String,
    pub issuer: String,
    pub destination: String,
    pub acs_url: String,
    pub protocol_binding: String,
    pub force_authn: bool,
    pub contexts: Vec<String>,
    pub login_hint: String,
}
pub fn parse_authn_request(encoded: &str) -> Result<AuthnRequest, Error> {
    let xml = decode_message(encoded)?;
    let document = bergshamra::xml::uppsala::parse(&xml).map_err(crypto_error)?;
    let root = document
        .document_element()
        .ok_or_else(|| Error::Validation("SAMLRequest root is required".into()))?;
    if !crypto::named(&document, root, PROTOCOL_NS, "AuthnRequest") {
        return Err(Error::Validation(
            "SAMLRequest must contain an AuthnRequest".into(),
        ));
    }
    let attribute = |name: &str| {
        document
            .get_attribute(root, name)
            .unwrap_or_default()
            .trim()
            .to_owned()
    };
    let issuer = document
        .children(root)
        .into_iter()
        .find(|node| {
            document
                .element(*node)
                .is_some_and(|element| element.name.local_name == "Issuer")
        })
        .map(|node| document.text_content_deep(node).trim().to_owned())
        .unwrap_or_default();
    let requested = document.children(root).into_iter().find(|node| {
        document
            .element(*node)
            .is_some_and(|element| element.name.local_name == "RequestedAuthnContext")
    });
    let contexts = requested
        .map(|requested| {
            document
                .children(requested)
                .into_iter()
                .filter(|node| {
                    document
                        .element(*node)
                        .is_some_and(|element| element.name.local_name == "AuthnContextClassRef")
                })
                .map(|node| document.text_content_deep(node).trim().to_owned())
                .filter(|value| !value.is_empty())
                .collect()
        })
        .unwrap_or_default();
    Ok(AuthnRequest {
        id: attribute("ID"),
        issuer,
        destination: attribute("Destination"),
        acs_url: attribute("AssertionConsumerServiceURL"),
        protocol_binding: attribute("ProtocolBinding"),
        force_authn: matches!(
            attribute("ForceAuthn").to_ascii_lowercase().as_str(),
            "true" | "1" | "yes" | "on"
        ),
        contexts,
        login_hint: ["NameID", "LoginHint", "login_hint"]
            .iter()
            .find_map(|name| first_local_text(&document, root, name))
            .unwrap_or_default(),
    })
}
fn first_local_text(
    document: &bergshamra::xml::Document<'_>,
    node: bergshamra::xml::NodeId,
    name: &str,
) -> Option<String> {
    if document
        .element(node)
        .is_some_and(|element| element.name.local_name == name)
    {
        let text = document.text_content_deep(node).trim().to_owned();
        if !text.is_empty() {
            return Some(text);
        }
    }
    document
        .children(node)
        .into_iter()
        .find_map(|child| first_local_text(document, child, name))
}
pub fn resolve_request(
    environment: &crate::model::Environment,
    base: &str,
    values: &crate::oidc::Parameters,
    raw_query: &str,
) -> Result<AuthnRequest, Error> {
    let settings = &environment.settings;
    let configured = settings.saml_acs_url.trim();
    if configured.is_empty() {
        return Err(Error::Validation(
            "SAML ACS URL must be configured on the app".into(),
        ));
    }
    let value = |name: &str| {
        values
            .get(name)
            .map(String::as_str)
            .unwrap_or_default()
            .trim()
    };
    if !value("acs_url").is_empty() && value("acs_url") != configured {
        return Err(Error::Validation(
            "SAML ACS URL does not match the configured app".into(),
        ));
    }
    if value("SAMLRequest").is_empty() {
        return Ok(AuthnRequest {
            acs_url: configured.into(),
            ..Default::default()
        });
    }
    if !settings.saml_request_certificate_pem.is_empty() {
        let redirect = url::form_urlencoded::parse(raw_query.as_bytes())
            .any(|(name, value)| name == "SAMLRequest" && !value.is_empty());
        if redirect {
            verify_redirect(
                raw_query,
                "SAMLRequest",
                "AuthnRequest",
                &settings.saml_request_certificate_pem,
            )?;
        } else {
            verify_xml(
                &decode_message(value("SAMLRequest"))?,
                &settings.saml_request_certificate_pem,
                "AuthnRequest",
            )?;
        }
    }
    let mut request = parse_authn_request(value("SAMLRequest"))?;
    if request.id.is_empty() {
        return Err(Error::Validation("SAML AuthnRequest ID is required".into()));
    }
    if !settings.saml_entity_id.trim().is_empty()
        && request.issuer != settings.saml_entity_id.trim()
    {
        return Err(Error::Validation(
            "SAML AuthnRequest issuer does not match the configured app".into(),
        ));
    }
    if !request.destination.is_empty()
        && request.destination
            != format!(
                "{}/saml/{}/sso",
                base.trim_end_matches('/'),
                environment.slug
            )
    {
        return Err(Error::Validation(
            "SAML AuthnRequest destination does not match this IDP".into(),
        ));
    }
    if !request.acs_url.is_empty() && request.acs_url != configured {
        return Err(Error::Validation(
            "SAML AuthnRequest ACS URL does not match the configured app".into(),
        ));
    }
    if !request.protocol_binding.is_empty() && request.protocol_binding != POST_BINDING {
        return Err(Error::Validation(
            "SAML AuthnRequest must request the HTTP-POST response binding".into(),
        ));
    }
    request.acs_url = configured.into();
    Ok(request)
}
pub fn verify_redirect(
    query: &str,
    message: &str,
    kind: &str,
    certificate_pem: &str,
) -> Result<(), Error> {
    use rsa::{Pkcs1v15Sign, RsaPublicKey, pkcs8::DecodePublicKey};
    use sha2::{Digest, Sha256, Sha384, Sha512};
    let raw_message = raw_value(query, message, true)?.unwrap_or_default();
    let relay = raw_value(query, "RelayState", false)?;
    let algorithm = raw_value(query, "SigAlg", true)?.unwrap_or_default();
    let signature = raw_value(query, "Signature", true)?.unwrap_or_default();
    let signed = format!(
        "{message}={raw_message}{}&SigAlg={algorithm}",
        relay
            .map(|relay| format!("&RelayState={relay}"))
            .unwrap_or_default()
    );
    let algorithm = query_decode(algorithm)?;
    let signature = STANDARD
        .decode(query_decode(signature)?)
        .map_err(|error| Error::Validation(format!("decode SAML Redirect Signature: {error}")))?;
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(certificate_pem.as_bytes()).map_err(crypto_error)?;
    let (_, certificate) =
        x509_parser::parse_x509_certificate(&pem.contents).map_err(crypto_error)?;
    let public =
        RsaPublicKey::from_public_key_der(certificate.public_key().raw).map_err(crypto_error)?;
    let result = match algorithm.as_str() {
        RSA_SHA256 => public.verify(
            Pkcs1v15Sign::new::<Sha256>(),
            &Sha256::digest(signed.as_bytes()),
            &signature,
        ),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => public.verify(
            Pkcs1v15Sign::new::<Sha384>(),
            &Sha384::digest(signed.as_bytes()),
            &signature,
        ),
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => public.verify(
            Pkcs1v15Sign::new::<Sha512>(),
            &Sha512::digest(signed.as_bytes()),
            &signature,
        ),
        _ => {
            return Err(Error::Validation(format!(
                "unsupported SAML Redirect signature algorithm {algorithm:?}"
            )));
        }
    };
    result.map_err(|_| Error::Validation(format!("invalid SAML {kind} signature")))
}
fn raw_value<'a>(query: &'a str, name: &str, required: bool) -> Result<Option<&'a str>, Error> {
    let mut value = None;
    for part in query.split('&') {
        let Some((key, candidate)) = part.split_once('=') else {
            continue;
        };
        if query_decode(key)? != name {
            continue;
        }
        if key != name {
            return Err(Error::Validation(format!(
                "SAML Redirect parameter name {name} must not be percent-encoded"
            )));
        }
        if value.is_some() {
            return Err(Error::Validation(format!(
                "SAML Redirect request contains duplicate {name} parameters"
            )));
        }
        value = Some(candidate);
    }
    if required && value.is_none_or(str::is_empty) {
        return Err(Error::Validation(format!(
            "signed SAML Redirect request requires {name}"
        )));
    }
    Ok(value)
}
fn query_decode(value: &str) -> Result<String, Error> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut input = value.bytes();
    while let Some(byte) = input.next() {
        match byte {
            b'+' => bytes.push(b' '),
            b'%' => {
                let hex = input
                    .next()
                    .zip(input.next())
                    .and_then(|(a, b)| (a as char).to_digit(16).zip((b as char).to_digit(16)))
                    .ok_or_else(|| {
                        Error::Validation("invalid URL escape in SAML Redirect query".into())
                    })?;
                bytes.push((hex.0 * 16 + hex.1) as u8);
            }
            byte => bytes.push(byte),
        }
    }
    String::from_utf8(bytes).map_err(|error| Error::Validation(error.to_string()))
}
