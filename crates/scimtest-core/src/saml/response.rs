use super::*;
use crate::{
    model::{Directory, Environment, User},
    oidc::Faults,
    signing::SigningKey,
};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashSet;

#[derive(Clone, Debug)]
pub struct ResponseContext {
    pub acs_url: String,
    pub in_response_to: String,
    pub assertion_id: String,
    pub session_index: String,
    pub authn_time: DateTime<Utc>,
    pub authn_context: String,
}
pub struct PostedResponse {
    pub xml: String,
    pub plaintext_assertion: String,
    pub assertion_id: String,
}

pub fn build_response(
    directory: &Directory,
    user: &User,
    key: &SigningKey,
    base: &str,
    context: &ResponseContext,
    faults: &Faults,
) -> Result<PostedResponse, Error> {
    let settings = &directory.environment.settings;
    let now = Utc::now() + faults.skew();
    let issuer = format!("{base}/saml/{}/metadata", directory.environment.slug);
    let response_id = crate::store::new_id("saml-response");
    let response_to = optional_attribute("InResponseTo", &context.in_response_to);
    let prefix = format!(
        r#"<samlp:Response xmlns:samlp="{PROTOCOL_NS}" xmlns:saml="{ASSERTION_NS}" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}"{response_to}>"#,
        xml_escape(&response_id),
        instant(now),
        xml_escape(&context.acs_url)
    );
    if let Some(status) = faults.saml_status_value() {
        let xml = format!(
            r#"{prefix}<saml:Issuer>{}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"><samlp:StatusCode Value="{status}"/></samlp:StatusCode></samlp:Status></samlp:Response>"#,
            xml_escape(&issuer)
        );
        return Ok(PostedResponse {
            xml,
            plaintext_assertion: String::new(),
            assertion_id: context.assertion_id.clone(),
        });
    }
    let assertion_id = if context.assertion_id.is_empty() {
        crate::store::new_id("saml-assertion")
    } else {
        context.assertion_id.clone()
    };
    let wrong = |value: &str, fault: &str| {
        if faults.tampers(fault) {
            if value.is_empty() {
                "scimtest-wrong".into()
            } else {
                format!("{value}-wrong")
            }
        } else {
            value.to_owned()
        }
    };
    let issuer = wrong(&issuer, "wrong_issuer");
    let audience = if !settings.saml_audience.is_empty() {
        &settings.saml_audience
    } else if !settings.saml_entity_id.is_empty() {
        &settings.saml_entity_id
    } else {
        &context.acs_url
    };
    let audience = wrong(audience, "wrong_audience");
    let recipient = wrong(&context.acs_url, "wrong_recipient");
    let destination = wrong(&context.acs_url, "wrong_destination");
    let response_to = optional_attribute(
        "InResponseTo",
        &wrong(&context.in_response_to, "in_response_to_mismatch"),
    );
    let expires = now
        + faults
            .assertion_ttl
            .as_deref()
            .and_then(crate::oidc::faults::duration)
            .unwrap_or(Duration::minutes(5));
    let not_before = if expires < now {
        expires - Duration::minutes(1)
    } else {
        now - Duration::minutes(1)
    };
    let name_id = if faults.tampers("nameid_comment") {
        format!(
            "{}{}",
            name_id(
                &directory.environment,
                super::wrapping::forgery_user(directory, user)?
            ),
            super::wrapping::FORGED_SUFFIX
        )
    } else {
        name_id(&directory.environment, user).to_owned()
    };
    let name_format = name_id_format(&directory.environment);
    let session = optional_attribute("SessionIndex", &context.session_index);
    let attributes = attributes(directory, user);
    let assertion = format!(
        r#"<saml:Assertion xmlns:saml="{ASSERTION_NS}" ID="{}" Version="2.0" IssueInstant="{}"><saml:Issuer>{}</saml:Issuer><saml:Subject><saml:NameID Format="{}">{}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData{response_to} NotOnOrAfter="{}" Recipient="{}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{}" NotOnOrAfter="{}"><saml:AudienceRestriction><saml:Audience>{}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{}"{session}><saml:AuthnContext><saml:AuthnContextClassRef>{}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement>{attributes}</saml:AttributeStatement></saml:Assertion>"#,
        xml_escape(&assertion_id),
        instant(now),
        xml_escape(&issuer),
        xml_escape(&name_format),
        xml_escape(&name_id),
        instant(expires),
        xml_escape(&recipient),
        instant(not_before),
        instant(expires),
        xml_escape(&audience),
        instant(context.authn_time + faults.skew()),
        xml_escape(&context.authn_context)
    );
    let (sign_assertion, sign_response) = match settings.saml_signing_mode.as_str() {
        "assertion" | "" => (true, false),
        "response" => (false, true),
        "both" => (true, true),
        _ => return Err(Error::Validation("unknown SAML signing mode".into())),
    };
    let mut assertion = if sign_assertion {
        sign_xml(&assertion, key)?
    } else {
        assertion
    };
    if sign_assertion && faults.break_signature {
        corrupt_signature(&mut assertion);
    }
    let mut plaintext_assertion = String::new();
    if !settings.saml_encryption_certificate_pem.is_empty() {
        if faults.tamper.iter().any(|fault| {
            ["xsw_assertion", "xsw_response", "nameid_comment"].contains(&fault.as_str())
        }) {
            return Err(Error::Validation("signature wrapping and NameID comment faults cannot combine with assertion encryption".into()));
        }
        plaintext_assertion = assertion.clone();
        assertion = encrypt_assertion(
            &assertion,
            &settings.saml_encryption_certificate_pem,
            &settings.saml_encryption_algorithm,
        )?;
    }
    let mut xml = format!(
        r#"<samlp:Response xmlns:samlp="{PROTOCOL_NS}" xmlns:saml="{ASSERTION_NS}" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}"{response_to}><saml:Issuer>{}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>{assertion}</samlp:Response>"#,
        xml_escape(&response_id),
        instant(now),
        xml_escape(&destination),
        xml_escape(&issuer)
    );
    if sign_response {
        xml = sign_xml(&xml, key)?;
        if faults.break_signature {
            corrupt_signature(&mut xml);
        }
    }
    xml = super::wrapping::apply(xml, directory, user, faults)?;
    Ok(PostedResponse {
        xml,
        plaintext_assertion,
        assertion_id,
    })
}
pub fn name_id<'a>(environment: &Environment, user: &'a User) -> &'a str {
    match environment.settings.saml_name_id_field.as_str() {
        "username" => &user.fields.username,
        "firstName" => &user.fields.given_name,
        "lastName" => &user.fields.family_name,
        _ => &user.fields.email,
    }
}
pub fn name_id_format(environment: &Environment) -> String {
    if !environment.settings.saml_name_id_format.is_empty() {
        return environment.settings.saml_name_id_format.clone();
    }
    if environment.settings.saml_name_id_field == "email"
        || environment.settings.saml_name_id_field.is_empty()
    {
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".into()
    } else {
        "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".into()
    }
}
impl PostedResponse {
    pub(crate) fn group_values(&self, name: &str) -> Option<(Vec<String>, bool)> {
        let source = if self.plaintext_assertion.is_empty() {
            &self.xml
        } else {
            &self.plaintext_assertion
        };
        let document = bergshamra::xml::uppsala::parse(source).ok()?;
        let root = document.document_element()?;
        let assertion = super::crypto::descendants(&document, root, ASSERTION_NS, "Assertion")
            .first()
            .copied()?;
        for attribute in super::crypto::descendants(&document, assertion, ASSERTION_NS, "Attribute")
        {
            if document
                .element(attribute)
                .and_then(|element| element.get_attribute("Name"))
                != Some(name)
            {
                continue;
            }
            let values =
                super::crypto::descendants(&document, attribute, ASSERTION_NS, "AttributeValue")
                    .iter()
                    .map(|node| document.text_content_deep(*node))
                    .collect();
            return Some((values, true));
        }
        Some((Vec::new(), false))
    }
}

fn attributes(directory: &Directory, user: &User) -> String {
    let settings = &directory.environment.settings;
    let mappings = &settings.saml_attribute_mappings;
    let mut attributes = String::new();
    let mut written = HashSet::new();
    let mut write = |name: &str, values: Vec<String>| {
        if !written.insert(name.to_owned()) {
            return;
        }
        attributes.push_str(&format!("<saml:Attribute Name=\"{}\">", xml_escape(name)));
        for value in values {
            attributes.push_str(&format!(
                "<saml:AttributeValue>{}</saml:AttributeValue>",
                xml_escape(&value)
            ));
        }
        attributes.push_str("</saml:Attribute>");
    };
    for (name, value) in [
        (&mappings.email, &user.fields.email),
        (&mappings.username, &user.fields.username),
        (&mappings.given_name, &user.fields.given_name),
        (&mappings.family_name, &user.fields.family_name),
    ] {
        write(name, vec![value.clone()]);
    }
    if settings.include_groups_claim {
        let mut groups = directory
            .projected_groups()
            .into_iter()
            .filter(|group| !group.deleted && group.fields.member_ids.contains(&user.id))
            .map(|group| group.fields.display_name)
            .collect::<Vec<_>>();
        groups.sort();
        write(&mappings.groups, groups);
    }
    for (name, value) in [
        ("employeeNumber", &user.fields.employee_number),
        ("costCenter", &user.fields.cost_center),
        ("organization", &user.fields.organization),
        ("division", &user.fields.division),
        ("department", &user.fields.department),
    ] {
        if !value.is_empty() {
            write(name, vec![value.clone()]);
        }
    }
    if let Some(manager) = directory.users.iter().find(|manager| {
        manager.id == user.fields.manager_id
            && !manager.deleted
            && !directory
                .user_sync
                .get(&manager.id)
                .is_some_and(|state| state.deleted)
    }) {
        write(
            "manager",
            vec![name_id(&directory.environment, manager).into()],
        );
    }
    for (name, value) in &user.fields.attributes {
        if !crate::directory::reserved_attribute(name) {
            write(name, vec![value.clone()]);
        }
    }
    attributes
}
pub(super) fn instant(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
pub(super) fn optional_attribute(name: &str, value: &str) -> String {
    if value.is_empty() {
        String::new()
    } else {
        format!(" {name}=\"{}\"", xml_escape(value))
    }
}
fn corrupt_signature(xml: &mut String) {
    if let Some(index) = xml
        .find("<ds:SignatureValue>")
        .map(|index| index + "<ds:SignatureValue>".len())
    {
        let replacement = if xml.as_bytes()[index] == b'A' {
            "B"
        } else {
            "A"
        };
        xml.replace_range(index..index + 1, replacement);
    }
}
