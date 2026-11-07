use base64::{Engine, engine::general_purpose::STANDARD};
use scimtest_core::saml::decode_message;
use std::io::Write;

fn assertion() -> String {
    r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_greendale-troy" Version="2.0" IssueInstant="2026-11-05T12:00:00Z"><saml:Issuer>https://greendale.example/saml/metadata</saml:Issuer><saml:Subject><saml:NameID>troy@greendale.edu</saml:NameID></saml:Subject></saml:Assertion>"#.into()
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
