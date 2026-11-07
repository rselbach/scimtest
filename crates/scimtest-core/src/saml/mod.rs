mod crypto;
mod logout;
mod metadata;
mod request;
mod response;
mod wrapping;
pub(crate) use logout::binding_name;
pub use logout::{
    LogoutMessage, LogoutStatus, OutboundMessage, STATUS_SUCCESS, build_logout_request,
    build_logout_response, encode_logout, parse_binding, read_logout,
};
pub use metadata::metadata;
pub use response::{PostedResponse, ResponseContext, build_response, name_id, name_id_format};

use crate::Error;
pub use crypto::{encrypt_assertion, sign_xml, verify_xml};
pub use request::{
    AuthnRequest, decode_message, parse_authn_request, resolve_request, verify_redirect,
};

pub const ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub const PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const POST_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
pub const REDIRECT_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub const C14N_EXCLUSIVE: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

pub(crate) fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn crypto_error(error: impl std::fmt::Display) -> Error {
    Error::Crypto(error.to_string())
}
