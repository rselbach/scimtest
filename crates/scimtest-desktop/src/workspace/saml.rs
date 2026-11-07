use super::Workspace;
mod view;
use gpui::Context;
use scimtest_core::oidc::{Faults, Parameters, ProtocolError, SamlAuthorization};
use serde_json::Value;

#[derive(Default)]
pub(super) struct Inspector {
    pub user: String,
    pub fault: &'static str,
    section: &'static str,
    mfa: bool,
    cookie: String,
    pub inspections: Vec<Value>,
    pub logouts: Vec<Value>,
}
impl Workspace {
    pub(super) fn run_saml(&mut self, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        let Some(directory) = self.directory() else {
            return;
        };
        let Some(user) = directory
            .projected_users()
            .into_iter()
            .filter(|user| user.fields.active && !user.deleted)
            .min_by_key(|user| user.id != self.saml.user)
        else {
            self.message = "Select an active user to run sign-in".into();
            self.failed = true;
            cx.notify();
            return;
        };
        let id = directory.environment.id.clone();
        let slug = directory.environment.slug.clone();
        let mut values = Parameters::from([
            ("user_id".into(), user.id),
            ("login_identifier".into(), user.fields.email),
            (
                "authn_strength".into(),
                if self.saml.mfa { "mfa" } else { "password" }.into(),
            ),
        ]);
        if let Some(faults) = fault(self.saml.fault) {
            if let Some(ttl) = faults.assertion_ttl {
                values.insert("fault_assertion_ttl".into(), ttl);
            }
            if faults.break_signature {
                values.insert("fault_break_signature".into(), "1".into());
            }
            if !faults.saml_status.is_empty() {
                values.insert("fault_saml_status".into(), faults.saml_status);
            }
            if !faults.tamper.is_empty() {
                values.insert("fault_tamper".into(), faults.tamper.join(","));
            }
        }
        let identity = self.identity.clone();
        let tunnel = self.tunnel_service.clone();
        let local_base = self.api_url.clone();
        let cookie = self.saml.cookie.clone();
        self.busy = true;
        cx.spawn(async move |view, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
                    let base = tunnel.effective_base(&local_base)?;
                    match identity.saml_sign_in(&slug, &values, &cookie, &base, "", true)? {
                        SamlAuthorization::Response { session, .. } => {
                            Ok::<_, ProtocolError>(session)
                        }
                        _ => Err(ProtocolError::new(
                            "invalid_request",
                            "active user is required",
                        )),
                    }
                })
                .await;
            let _ = view.update(cx, |view, cx| {
                view.busy = false;
                if view.selected.as_ref() == Some(&id) {
                    view.status_revision = view.status_revision.wrapping_add(1);
                    match result {
                        Ok(cookie) => {
                            view.saml.cookie = cookie;
                            view.message = "SAML response generated".into();
                            view.failed = false;
                        }
                        Err(error) => {
                            view.message = error.description;
                            view.failed = true;
                        }
                    }
                    view.refresh_identity(cx);
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }
    pub(super) fn saml_browser_logout(
        &mut self,
        session: String,
        binding: &'static str,
        cx: &mut Context<Self>,
    ) {
        self.saml_browser_request(
            move |identity, id, base| identity.start_saml_logout(id, &session, binding, base),
            cx,
        );
    }
    pub(super) fn saml_browser_request(
        &mut self,
        action: impl FnOnce(
            scimtest_core::oidc::Identity,
            &str,
            &str,
        ) -> Result<scimtest_core::saml::OutboundMessage, ProtocolError>
        + Send
        + 'static,
        cx: &mut Context<Self>,
    ) {
        if self.busy {
            return;
        }
        let Some(directory) = self.directory() else {
            return;
        };
        let id = directory.environment.id.clone();
        let slug = directory.environment.slug.clone();
        let identity = self.identity.clone();
        let tunnel = self.tunnel_service.clone();
        let local_base = self.api_url.clone();
        let delivery_base = local_base.clone();
        let request_id = id.clone();
        self.busy = true;
        cx.spawn(async move |view, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
                    let base = tunnel.effective_base(&local_base)?;
                    let message = action(identity.clone(), &request_id, &base)?;
                    let ticket = identity.stage_saml_delivery(&request_id, message)?;
                    Ok::<_, ProtocolError>(format!("{delivery_base}/saml/{slug}/continue/{ticket}"))
                })
                .await;
            let _ = view.update(cx, |view, cx| {
                view.busy = false;
                match result {
                    Ok(url) => {
                        cx.open_url(&url);
                        view.message = "Logout request opened in your browser".into();
                        view.failed = false;
                    }
                    Err(error) => {
                        view.message = error.description;
                        view.failed = true;
                    }
                }
                if view.selected.as_ref() == Some(&id) {
                    view.refresh_identity(cx);
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }
}
pub(super) fn fault(name: &str) -> Option<Faults> {
    let mut fault = Faults::default();
    match name {
        "Expired assertion" => fault.assertion_ttl = Some("-1m".into()),
        "Broken signature" => fault.break_signature = true,
        "Authentication failed" => fault.saml_status = "AuthnFailed".into(),
        "Wrong issuer" => fault.tamper = vec!["wrong_issuer".into()],
        "Wrong audience" => fault.tamper = vec!["wrong_audience".into()],
        "Wrong destination" => fault.tamper = vec!["wrong_destination".into()],
        "Wrong recipient" => fault.tamper = vec!["wrong_recipient".into()],
        "Mismatched request" => fault.tamper = vec!["in_response_to_mismatch".into()],
        "Replayed assertion" => fault.tamper = vec!["replayed_assertion".into()],
        "Assertion wrapping" => fault.tamper = vec!["xsw_assertion".into()],
        "Response wrapping" => fault.tamper = vec!["xsw_response".into()],
        "NameID comment" => fault.tamper = vec!["nameid_comment".into()],
        _ => return None,
    }
    Some(fault)
}
