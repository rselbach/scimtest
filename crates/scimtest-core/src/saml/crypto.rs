use super::*;
use crate::signing::SigningKey;
use aes_gcm::{
    Aes128Gcm, Aes256Gcm, AesGcm,
    aead::{Aead, KeyInit, consts::U12},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use bergshamra::{
    DsigContext, KeysManager,
    xml::{Document, NodeId, uppsala},
};
use rand::RngCore;
use rsa::{Oaep, RsaPublicKey, pkcs8::DecodePublicKey};
use sha1::Sha1;

pub fn sign_xml(xml: &str, key: &SigningKey) -> Result<String, Error> {
    let document = uppsala::parse(xml).map_err(crypto_error)?;
    let root = document
        .document_element()
        .ok_or_else(|| Error::Validation("SAML root element is required".into()))?;
    let id = document
        .element(root)
        .and_then(|root| root.get_attribute("ID"))
        .filter(|id| !id.is_empty())
        .ok_or_else(|| Error::Validation("SAML message ID is required".into()))?;
    let id = xml_escape(id);
    let certificate = STANDARD.encode(&key.certificate);
    let signature = format!(
        r##"<ds:Signature xmlns:ds="{DSIG_NS}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{C14N_EXCLUSIVE}"/><ds:SignatureMethod Algorithm="{RSA_SHA256}"/><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="{DSIG_NS}enveloped-signature"/><ds:Transform Algorithm="{C14N_EXCLUSIVE}"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"##
    );
    let index = xml
        .find("</saml:Issuer>")
        .map(|index| index + "</saml:Issuer>".len())
        .ok_or_else(|| Error::Validation("SAML signing requires an Issuer".into()))?;
    let template = format!("{}{}{}", &xml[..index], signature, &xml[index..]);
    let mut private =
        bergshamra::keys::loader::load_rsa_private_pem(key.stored.private_key_pem.as_bytes())
            .map_err(crypto_error)?;
    private.x509_chain.push(key.certificate.clone());
    let mut keys = KeysManager::new();
    keys.add_key(private);
    bergshamra::dsig::sign::sign_owned(&DsigContext::new(keys), template).map_err(crypto_error)
}
pub fn verify_xml(xml: &str, certificate_pem: &str, kind: &str) -> Result<(), Error> {
    let document = uppsala::parse(xml).map_err(crypto_error)?;
    let root = document
        .document_element()
        .ok_or_else(|| Error::Validation("SAML root element is required".into()))?;
    let id = document
        .element(root)
        .and_then(|element| element.get_attribute("ID"))
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            Error::Validation(format!(
                "SAML {kind} ID is required before signature validation"
            ))
        })?;
    let signatures = descendants(&document, root, DSIG_NS, "Signature");
    if signatures.len() != 1 || document.parent(signatures[0]) != Some(root) {
        return Err(Error::Validation(format!(
            "SAML {kind} must contain exactly one direct XMLDSIG signature"
        )));
    }
    let signature = signatures[0];
    let info = child(&document, signature, DSIG_NS, "SignedInfo")
        .ok_or_else(|| Error::Validation("SAML signature has no SignedInfo".into()))?;
    let method = child(&document, info, DSIG_NS, "SignatureMethod")
        .and_then(|node| document.element(node))
        .and_then(|element| element.get_attribute("Algorithm"))
        .unwrap_or_default();
    if ![
        RSA_SHA256,
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
    ]
    .contains(&method)
    {
        return Err(Error::Validation(format!(
            "unsupported SAML XML signature algorithm {method:?}"
        )));
    }
    let references = document
        .children(info)
        .into_iter()
        .filter(|node| named(&document, *node, DSIG_NS, "Reference"))
        .collect::<Vec<_>>();
    if references.len() != 1 {
        return Err(Error::Validation(format!(
            "SAML {kind} signature must contain one reference"
        )));
    }
    let reference = references[0];
    if document
        .element(reference)
        .and_then(|element| element.get_attribute("URI"))
        != Some(format!("#{id}").as_str())
    {
        return Err(Error::Validation(format!(
            "SAML {kind} signature must reference the message ID"
        )));
    }
    let digest = child(&document, reference, DSIG_NS, "DigestMethod")
        .and_then(|node| document.element(node))
        .and_then(|element| element.get_attribute("Algorithm"))
        .unwrap_or_default();
    if ![
        "http://www.w3.org/2001/04/xmlenc#sha256",
        "http://www.w3.org/2001/04/xmldsig-more#sha384",
        "http://www.w3.org/2001/04/xmlenc#sha512",
    ]
    .contains(&digest)
    {
        return Err(Error::Validation(format!(
            "SAML {kind} signature must use SHA-256, SHA-384, or SHA-512"
        )));
    }
    let key = bergshamra::keys::loader::load_x509_cert_pem(certificate_pem.as_bytes())
        .map_err(crypto_error)?;
    let mut keys = KeysManager::new();
    keys.add_key(key);
    match bergshamra::verify(&DsigContext::new(keys), xml).map_err(crypto_error)? {
        bergshamra::VerifyResult::Valid { .. } => Ok(()),
        _ => Err(Error::Validation(format!("invalid SAML {kind} signature"))),
    }
}
pub fn encrypt_assertion(
    xml: &str,
    certificate_pem: &str,
    algorithm: &str,
) -> Result<String, Error> {
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(certificate_pem.as_bytes()).map_err(crypto_error)?;
    let (_, certificate) =
        x509_parser::parse_x509_certificate(&pem.contents).map_err(crypto_error)?;
    let public =
        RsaPublicKey::from_public_key_der(certificate.public_key().raw).map_err(crypto_error)?;
    let length = match algorithm {
        "aes128-gcm" => 16,
        "aes192-gcm" => 24,
        "aes256-gcm" => 32,
        _ => {
            return Err(Error::Validation(
                "unsupported SAML assertion encryption algorithm".into(),
            ));
        }
    };
    let mut key = vec![0u8; length];
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut key);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let plaintext = bergshamra::c14n::canonicalize(
        xml,
        bergshamra::c14n::C14nMode::Exclusive,
        None,
        &[] as &[&str],
    )
    .map_err(crypto_error)?;
    let ciphertext = match length {
        16 => Aes128Gcm::new_from_slice(&key)
            .map_err(crypto_error)?
            .encrypt((&nonce).into(), plaintext.as_ref())
            .map_err(crypto_error)?,
        24 => AesGcm::<aes::Aes192, U12>::new_from_slice(&key)
            .map_err(crypto_error)?
            .encrypt((&nonce).into(), plaintext.as_ref())
            .map_err(crypto_error)?,
        _ => Aes256Gcm::new_from_slice(&key)
            .map_err(crypto_error)?
            .encrypt((&nonce).into(), plaintext.as_ref())
            .map_err(crypto_error)?,
    };
    let wrapped = public
        .encrypt(&mut rand::rngs::OsRng, Oaep::new::<Sha1>(), &key)
        .map_err(crypto_error)?;
    let data = STANDARD.encode([nonce.as_slice(), ciphertext.as_slice()].concat());
    let wrapped = STANDARD.encode(wrapped);
    let certificate = STANDARD.encode(&pem.contents);
    Ok(format!(
        r#"<saml:EncryptedAssertion xmlns:saml="{ASSERTION_NS}"><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="{DSIG_NS}" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#{algorithm}"/><ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{wrapped}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{data}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>"#
    ))
}
pub(super) fn named(document: &Document<'_>, node: NodeId, namespace: &str, name: &str) -> bool {
    document.element(node).is_some_and(|element| {
        element.name.local_name == name && element.name.namespace_uri.as_deref() == Some(namespace)
    })
}
pub(super) fn child(
    document: &Document<'_>,
    node: NodeId,
    namespace: &str,
    name: &str,
) -> Option<NodeId> {
    document
        .children(node)
        .into_iter()
        .find(|node| named(document, *node, namespace, name))
}
pub(super) fn descendants(
    document: &Document<'_>,
    root: NodeId,
    namespace: &str,
    name: &str,
) -> Vec<NodeId> {
    let mut nodes = Vec::new();
    if named(document, root, namespace, name) {
        nodes.push(root);
    }
    for child in document.children(root) {
        nodes.extend(descendants(document, child, namespace, name));
    }
    nodes
}
