use super::*;
use crate::{Store, model::Environment};
use base64::{Engine, engine::general_purpose::STANDARD};

pub fn metadata(store: &Store, environment: &Environment, base: &str) -> Result<String, Error> {
    let keys = store.published_signing_keys(&environment.id, chrono::Utc::now())?;
    let mut descriptors = String::new();
    for key in keys {
        descriptors.push_str(&format!(r#"<KeyDescriptor use="signing"><KeyInfo xmlns="{DSIG_NS}"><X509Data><X509Certificate>{}</X509Certificate></X509Data></KeyInfo></KeyDescriptor>"#,STANDARD.encode(key.certificate)));
    }
    let endpoint = format!("{base}/saml/{}", environment.slug);
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{}/metadata"><IDPSSODescriptor protocolSupportEnumeration="{PROTOCOL_NS}">{descriptors}<SingleLogoutService Binding="{REDIRECT_BINDING}" Location="{}/slo"/><SingleLogoutService Binding="{POST_BINDING}" Location="{}/slo"/><NameIDFormat>{}</NameIDFormat><SingleSignOnService Binding="{REDIRECT_BINDING}" Location="{}/sso"/><SingleSignOnService Binding="{POST_BINDING}" Location="{}/sso"/></IDPSSODescriptor></EntityDescriptor>"#,
        xml_escape(&endpoint),
        xml_escape(&endpoint),
        xml_escape(&endpoint),
        xml_escape(&response::name_id_format(environment)),
        xml_escape(&endpoint),
        xml_escape(&endpoint)
    ))
}
