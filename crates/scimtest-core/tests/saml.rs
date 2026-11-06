#[allow(dead_code)]
mod support;
use base64::{Engine, engine::general_purpose::STANDARD};
use scimtest_core::{
    Store,
    saml::{decode_message, encrypt_assertion, sign_xml, verify_xml},
};
use serde_json::{Value, json};
use std::io::Write;

fn assertion() -> String {
    r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_greendale-troy" Version="2.0" IssueInstant="2026-11-05T12:00:00Z"><saml:Issuer>https://greendale.example/saml/metadata</saml:Issuer><saml:Subject><saml:NameID>troy@greendale.edu</saml:NameID></saml:Subject></saml:Assertion>"#.into()
}
fn response(assertion: &str) -> String {
    format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_greendale-response" Version="2.0"><saml:Issuer>https://greendale.example/saml/metadata</saml:Issuer>{assertion}</samlp:Response>"#
    )
}
#[test]
fn rust_xml_signatures_verify_in_go_and_pinned_verification_rejects_other_keys() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("state.db");
    let store = Store::open(&path).unwrap();
    let key = store.shared_signing_key().unwrap();
    let assertion = sign_xml(&assertion(), &key).unwrap();
    verify_xml(&assertion, &key.stored.certificate_pem, "Assertion").unwrap();
    let xml = sign_xml(&response(&assertion), &key).unwrap();
    let result = support::bridge_input(
        "verify-saml",
        &path,
        &serde_json::to_vec(&json!({"xml":xml,"certificate_pem":key.stored.certificate_pem}))
            .unwrap(),
    );
    let result: Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(result["response_valid"], true);
    assert_eq!(result["assertion_valid"], true);
    assert!(
        verify_xml(
            &assertion.replace("troy@greendale.edu", "abed@greendale.edu"),
            &key.stored.certificate_pem,
            "Assertion"
        )
        .is_err()
    );
    let second = scimtest_core::signing::SigningKey::generate(
        "city-college".into(),
        scimtest_core::signing::CertificateValidity::Standard,
        chrono::Utc::now(),
    )
    .unwrap();
    assert!(verify_xml(&assertion, &second.stored.certificate_pem, "Assertion").is_err());
}
#[test]
fn go_decrypts_all_rust_assertion_encryption_modes_and_verifies_both_signatures() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("state.db");
    let store = Store::open(&path).unwrap();
    let key = store.shared_signing_key().unwrap();
    let assertion = sign_xml(&assertion(), &key).unwrap();
    for algorithm in ["aes128-gcm", "aes192-gcm", "aes256-gcm"] {
        let encrypted =
            encrypt_assertion(&assertion, &key.stored.certificate_pem, algorithm).unwrap();
        let xml = sign_xml(&response(&encrypted), &key).unwrap();
        let result=support::bridge_input("verify-saml",&path,&serde_json::to_vec(&json!({"xml":xml,"certificate_pem":key.stored.certificate_pem,"private_key_pem":key.stored.private_key_pem})).unwrap());
        let result: Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(result["response_valid"], true, "{algorithm}");
        assert_eq!(result["assertion_valid"], true, "{algorithm}");
        assert!(
            result["plaintext_assertion"]
                .as_str()
                .unwrap()
                .contains("troy@greendale.edu")
        );
    }
}
#[test]
fn saml_messages_accept_raw_xml_and_redirect_deflate_and_bound_expansion() {
    let xml = assertion();
    assert_eq!(decode_message(&STANDARD.encode(&xml)).unwrap(), xml);
    let mut deflate =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    deflate.write_all(xml.as_bytes()).unwrap();
    assert_eq!(
        decode_message(&STANDARD.encode(deflate.finish().unwrap())).unwrap(),
        xml
    );
    let mut deflate =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    deflate.write_all(&vec![b' '; (1 << 20) + 1]).unwrap();
    assert!(
        decode_message(&STANDARD.encode(deflate.finish().unwrap()))
            .unwrap_err()
            .to_string()
            .contains("exceeds 1048576 bytes")
    );
}

#[test]
fn configured_saml_responses_preserve_attributes_and_all_signing_modes() {
    use scimtest_core::{
        configuration::SettingsPatch,
        model::*,
        oidc::Faults,
        saml::{ResponseContext, build_response},
    };
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("state.db");
    let store = Store::open(&path).unwrap();
    let environment = store
        .create_environment(EnvironmentInput {
            name: "Greendale".into(),
            settings: SettingsPatch {
                saml_enabled: Some(true),
                saml_entity_id: Some("urn:greendale:sp".into()),
                saml_acs_url: Some("https://greendale.example/acs".into()),
                include_groups_claim: Some(true),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
    let manager = store
        .create_user(
            &environment.id,
            UserInput {
                given_name: "Abed".into(),
                family_name: "Nadir".into(),
                email: "abed@greendale.edu".into(),
                ..Default::default()
            },
        )
        .unwrap();
    let user = store
        .create_user(
            &environment.id,
            UserInput {
                given_name: "Troy".into(),
                family_name: "Barnes".into(),
                email: "troy@greendale.edu".into(),
                employee_number: "GCC42".into(),
                manager_id: manager.id,
                attributes: std::collections::BTreeMap::from([(
                    "favorite_class".into(),
                    "Air Conditioning & Repair".into(),
                )]),
                ..Default::default()
            },
        )
        .unwrap();
    store
        .create_group(
            &environment.id,
            GroupInput {
                display_name: "Study & Group".into(),
                member_ids: vec![user.id.clone()],
            },
        )
        .unwrap();
    let key = store.active_signing_key(&environment.id).unwrap();
    let context = ResponseContext {
        acs_url: environment.settings.saml_acs_url.clone(),
        in_response_to: "_authn_42".into(),
        assertion_id: String::new(),
        session_index: "greendale-session".into(),
        authn_time: chrono::Utc::now(),
        authn_context: "https://refeds.org/profile/mfa".into(),
    };
    for mode in ["assertion", "response", "both"] {
        store
            .update_environment(
                &environment.id,
                EnvironmentPatch {
                    settings: SettingsPatch {
                        saml_signing_mode: Some(mode.into()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .unwrap();
        let directory = store.directory(&environment.id).unwrap();
        let posted = build_response(
            &directory,
            &user,
            &key,
            "https://greendale.example",
            &context,
            &Faults::default(),
        )
        .unwrap();
        let result = support::bridge_input(
            "verify-saml",
            &path,
            &serde_json::to_vec(
                &json!({"xml":posted.xml,"certificate_pem":key.stored.certificate_pem}),
            )
            .unwrap(),
        );
        let result: Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(result["response_valid"], mode != "assertion");
        assert_eq!(result["assertion_valid"], mode != "response");
        let doc = bergshamra::xml::uppsala::parse(&posted.xml).unwrap();
        let attribute = doc
            .get_elements_by_tag_name("Attribute")
            .into_iter()
            .find(|node| doc.get_attribute(*node, "Name") == Some("manager"))
            .unwrap();
        assert_eq!(doc.text_content_deep(attribute), "abed@greendale.edu");
        let attribute = doc
            .get_elements_by_tag_name("Attribute")
            .into_iter()
            .find(|node| doc.get_attribute(*node, "Name") == Some("favorite_class"))
            .unwrap();
        assert_eq!(
            doc.text_content_deep(attribute),
            "Air Conditioning & Repair"
        );
        let name = doc.get_elements_by_tag_name("NameID")[0];
        assert_eq!(doc.text_content_deep(name), "troy@greendale.edu");
        let authn = doc.get_elements_by_tag_name("AuthnStatement")[0];
        assert_eq!(
            doc.get_attribute(authn, "SessionIndex"),
            Some("greendale-session")
        );
    }
    store
        .update_environment(
            &environment.id,
            EnvironmentPatch {
                settings: SettingsPatch {
                    saml_encryption_certificate_pem: Some(key.stored.certificate_pem.clone()),
                    saml_encryption_algorithm: Some("aes192-gcm".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    let directory = store.directory(&environment.id).unwrap();
    let posted = build_response(
        &directory,
        &user,
        &key,
        "https://greendale.example",
        &context,
        &Faults::default(),
    )
    .unwrap();
    assert!(!posted.xml.contains("troy@greendale.edu"));
    assert!(posted.plaintext_assertion.contains("troy@greendale.edu"));
    let result=support::bridge_input("verify-saml",&path,&serde_json::to_vec(&json!({"xml":posted.xml,"certificate_pem":key.stored.certificate_pem,"private_key_pem":key.stored.private_key_pem})).unwrap());
    let result: Value = serde_json::from_slice(&result).unwrap();
    assert_eq!(result["response_valid"], true);
    assert_eq!(result["assertion_valid"], true);
    let failed = build_response(
        &directory,
        &user,
        &key,
        "https://greendale.example",
        &context,
        &Faults {
            saml_status: "AuthnFailed".into(),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(failed.xml.contains("status:AuthnFailed"));
    assert!(!failed.xml.contains("<saml:Assertion"));
}
