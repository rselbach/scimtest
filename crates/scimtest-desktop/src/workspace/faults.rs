use super::{Editor, Workspace, editor::field, input};
use crate::dropdown::DropdownMenu;
use crate::theme::Palette;
use gpui::{Context, Div, Entity, Window, div, prelude::*};
use gpui_component::{
    Disableable, StyledExt, button::Button, checkbox::Checkbox, input::InputState,
    menu::PopupMenuItem,
};
use scimtest_core::{Error, oidc::Faults};
use std::collections::BTreeSet;

pub(super) struct Form {
    fields: [Entity<InputState>; 5],
    break_signature: bool,
    status: &'static str,
    tamper: BTreeSet<String>,
    oidc: bool,
    saml: bool,
}

impl Form {
    pub fn inputs(&self) -> Vec<gpui_component::input::AnyInputState> {
        self.fields
            .iter()
            .cloned()
            .map(gpui_component::input::AnyInputState::Input)
            .collect()
    }

    pub fn values(&self, cx: &Context<Workspace>) -> Result<Faults, Error> {
        let values = self
            .fields
            .each_ref()
            .map(|field| field.read(cx).value().to_string());
        let faults = Faults {
            id_token_ttl: Some(values[0].clone()),
            assertion_ttl: Some(values[1].clone()),
            clock_skew: Some(values[2].clone()),
            drop_claims: vec![values[3].clone()],
            token_error: values[4].clone(),
            break_signature: self.break_signature,
            saml_status: self.status.into(),
            tamper: self.tamper.iter().cloned().collect(),
        }
        .normalized()?;
        if !faults.active() {
            return Err(Error::Validation("Choose at least one fault".into()));
        }
        Ok(faults)
    }
    pub fn fields(&self, busy: bool, cx: &mut Context<Workspace>) -> Div {
        let palette = Palette::get(cx);
        let mut body = div().v_flex().gap_4().child(
            div().text_color(palette.muted).child("Arms the next matching flow. Logout faults wait for a back-channel logout. Leave durations empty to keep the normal lifetime; 0s explicitly expires immediately."),
        );
        let mut lifetimes = div().h_flex().gap_4().items_start();
        if self.oidc {
            lifetimes = lifetimes.child(field("ID token lifetime (e.g. -1m)", &self.fields[0]));
        }
        if self.saml {
            lifetimes = lifetimes.child(field("Assertion lifetime (e.g. -1m)", &self.fields[1]));
        }
        body = body
            .child(lifetimes)
            .child(field("Clock skew (e.g. 5m or -1h)", &self.fields[2]))
            .child(
                Checkbox::new("fault-break-signature")
                    .label("Break signatures")
                    .checked(self.break_signature)
                    .disabled(busy)
                    .on_click(cx.listener(|view, checked: &bool, _, cx| {
                        if let Some(Editor::Faults(form)) = &mut view.editor {
                            form.break_signature = *checked;
                            view.editor_dirty = true;
                        }
                        cx.notify();
                    })),
            )
            .child(field(
                "OIDC claims to remove (comma separated)",
                &self.fields[3],
            ));
        if self.oidc {
            body = body.child(field(
                "Token endpoint error (e.g. temporarily_unavailable)",
                &self.fields[4],
            ));
        }
        if self.saml {
            let view = cx.weak_entity();
            let status = if self.status.is_empty() {
                "Success"
            } else {
                self.status
            };
            body = body.child(
                div().h_flex().gap_3().child("SAML status").child(
                    Button::new("fault-saml-status")
                        .accessibility_label(format!("SAML status: {status}"))
                        .label(status)
                        .disabled(busy)
                        .dropdown_menu(move |mut menu, _, _| {
                            for status in ["", "Responder", "AuthnFailed"] {
                                let view = view.clone();
                                menu = menu.item(
                                    PopupMenuItem::new(if status.is_empty() {
                                        "Success"
                                    } else {
                                        status
                                    })
                                    .on_click(
                                        move |_, _, cx| {
                                            let _ = view.update(cx, |view, cx| {
                                                if let Some(Editor::Faults(form)) = &mut view.editor
                                                {
                                                    form.status = status;
                                                    view.editor_dirty = true;
                                                }
                                                cx.notify();
                                            });
                                        },
                                    ),
                                );
                            }
                            menu
                        }),
                ),
            );
        }
        body = body.child(
            div()
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child("Tamper with validation"),
        );
        for (id, label, protocol) in [
            ("wrong_issuer", "Wrong issuer", "both"),
            ("wrong_audience", "Wrong audience", "both"),
            ("unknown_kid", "Unknown signing key ID", "oidc"),
            ("alg_none", "Unsigned ID token (alg none)", "oidc"),
            ("nonce_mismatch", "Nonce mismatch", "oidc"),
            ("wrong_destination", "Wrong destination", "saml"),
            ("wrong_recipient", "Wrong recipient", "saml"),
            ("in_response_to_mismatch", "InResponseTo mismatch", "saml"),
            ("replayed_assertion", "Replayed assertion ID", "saml"),
            (
                "xsw_assertion",
                "Signature wrapping (signed assertion)",
                "saml",
            ),
            (
                "xsw_response",
                "Signature wrapping (signed response)",
                "saml",
            ),
            ("nameid_comment", "NameID comment injection", "saml"),
            (
                "logout_alg_none",
                "Logout token: unsigned (alg none)",
                "oidc",
            ),
            (
                "logout_wrong_audience",
                "Logout token: wrong audience",
                "oidc",
            ),
            (
                "logout_missing_events",
                "Logout token: missing events",
                "oidc",
            ),
            ("logout_repeated_jti", "Logout token: repeated jti", "oidc"),
        ] {
            if protocol == "oidc" && !self.oidc || protocol == "saml" && !self.saml {
                continue;
            }
            body = body.child(
                Checkbox::new(id)
                    .label(label)
                    .checked(self.tamper.contains(id))
                    .disabled(busy)
                    .on_click(cx.listener(move |view, checked: &bool, _, cx| {
                        if let Some(Editor::Faults(form)) = &mut view.editor {
                            if *checked {
                                form.tamper.insert(id.into());
                            } else {
                                form.tamper.remove(id);
                            }
                            view.editor_dirty = true;
                        }
                        cx.notify();
                    })),
            );
        }
        body
    }
}

impl Workspace {
    pub(super) fn edit_faults(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(directory) = self.directory() else {
            return;
        };
        let oidc = directory.environment.settings.supports_oidc();
        let saml = directory.environment.settings.supports_saml();
        let faults = &self.resilience.manual;
        let values = [
            faults.id_token_ttl.clone().unwrap_or_default(),
            faults.assertion_ttl.clone().unwrap_or_default(),
            faults.clock_skew.clone().unwrap_or_default(),
            faults.drop_claims.join(", "),
            faults.token_error.clone(),
        ];
        let fields = values.map(|value| input(&value, "", window, cx));
        self.editor = Some(Editor::Faults(Form {
            fields,
            oidc,
            saml,
            break_signature: faults.break_signature,
            status: match faults.saml_status.as_str() {
                "Responder" => "Responder",
                "AuthnFailed" => "AuthnFailed",
                _ => "",
            },
            tamper: faults.tamper.iter().cloned().collect(),
        }));
        self.message.clear();
        self.failed = false;
        cx.notify();
    }
}
