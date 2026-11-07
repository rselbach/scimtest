use rune::{El, ScrollSpec, Tx, col, row, text as label_text};
use rune_kit::{Button, ButtonVariant};
use serde_json::Value;

use super::{
    super::{
        Workspace,
        oidc::view::{code_panel, open, text},
        view::{Choice, copy_button, dropdown, empty, font_text},
    },
    fault,
};
use crate::theme::{SEMIBOLD, Ui};

const SECTIONS: [&str; 5] = [
    "Sign-in",
    "Sessions & logout",
    "Inspections",
    "Flow activity",
    "Signing keys",
];

const FAULTS: [&str; 13] = [
    "Healthy sign-in",
    "Expired assertion",
    "Broken signature",
    "Authentication failed",
    "Wrong issuer",
    "Wrong audience",
    "Wrong destination",
    "Wrong recipient",
    "Mismatched request",
    "Replayed assertion",
    "Assertion wrapping",
    "Response wrapping",
    "NameID comment",
];

impl Workspace {
    pub(in crate::workspace) fn saml_inspector(&self, ui: &Ui, layer: &mut Vec<El>) -> El {
        let p = ui.p;
        let selected = if self.saml.section.is_empty() {
            "Sign-in"
        } else {
            self.saml.section
        };
        let mut tabs = row().gap(8.0).pb(16.0);
        for section in SECTIONS {
            let current = selected == section;
            let mut tab = Button::new(section)
                .variant(ButtonVariant::Ghost)
                .on_press(move |s: &mut Workspace| s.saml.section = section);
            if current {
                tab = tab.label_with(move |font, _| label_text(section).font(font).color(p.accent));
            }
            let mut tab = tab.build(&ui.k).key(section).checked(current);
            if current {
                tab = tab.fill(p.selected);
            }
            tabs = tabs.child(tab);
        }
        let body = match selected {
            "Sessions & logout" => self.saml_sessions(ui),
            "Inspections" => self.saml_history(ui),
            "Flow activity" => self.flow_activity(ui),
            "Signing keys" => self.signing_controls(ui, layer),
            _ => self.saml_sign_in(ui, layer),
        };
        col().w_full().min_h(0.0).child(tabs).child(
            col()
                .key("saml-scroll")
                .w_full()
                .grow(1.0)
                .min_h(0.0)
                .scroll(ScrollSpec {
                    stick_bottom: false,
                })
                .child(body),
        )
    }

    fn saml_sign_in(&self, ui: &Ui, layer: &mut Vec<El>) -> El {
        let k = &ui.k;
        let users = self.active_users();
        let user = users
            .iter()
            .find(|user| user.id == self.saml.user)
            .or_else(|| users.first());
        let label = user
            .map(|user| format!("{} {}", user.fields.given_name, user.fields.family_name))
            .unwrap_or_else(|| "Choose account".into());
        let selected = user.map(|user| user.id.clone()).unwrap_or_default();
        let accounts = users
            .iter()
            .map(|user| {
                let id = user.id.clone();
                Choice::new(
                    format!(
                        "{} {} · {}",
                        user.fields.given_name, user.fields.family_name, user.fields.email
                    ),
                    move |s: &mut Workspace| s.saml.user = id.clone(),
                )
                .checked(user.id == selected)
            })
            .collect();
        let faults = FAULTS
            .into_iter()
            .map(|label| {
                let value = if label == "Healthy sign-in" {
                    ""
                } else {
                    label
                };
                Choice::new(label, move |s: &mut Workspace| s.saml.fault = value)
                    .checked(self.saml.fault == value)
            })
            .collect();
        let selected_fault = fault(self.saml.fault);
        let mut body = col().w_full().gap(16.0).child(
            row()
                .gap(8.0)
                .center_y()
                .flex_wrap()
                .child(dropdown(
                    self,
                    "saml-account",
                    label,
                    None,
                    self.busy,
                    accounts,
                    ui,
                    layer,
                ))
                .child(dropdown(
                    self,
                    "saml-fault",
                    if self.saml.fault.is_empty() {
                        "Healthy sign-in"
                    } else {
                        self.saml.fault
                    },
                    None,
                    self.busy,
                    faults,
                    ui,
                    layer,
                ))
                .child(
                    Button::new(if self.saml.mfa { "MFA" } else { "Password" })
                        .disabled(self.busy)
                        .on_press(|s: &mut Workspace| s.saml.mfa = !s.saml.mfa)
                        .build(k)
                        .key("saml-strength"),
                )
                .child(
                    Button::new("Arm fault")
                        .disabled(self.busy || selected_fault.is_none())
                        .on_press(move |s: &mut Workspace| {
                            if let Some(faults) = selected_fault.clone() {
                                s.identity_command(move |identity, id| {
                                    identity.arm_faults(&id, faults)?;
                                    Ok("Fault armed for the next sign-in".into())
                                });
                            }
                        })
                        .build(k)
                        .key("saml-arm-fault"),
                ),
        );
        if let Some(directory) = self.directory() {
            let metadata = format!(
                "{}/saml/{}/metadata",
                self.api_url, directory.environment.slug
            );
            let sign_in = format!("{}/saml/{}/sso", self.api_url, directory.environment.slug);
            body = body.child(
                row()
                    .gap(8.0)
                    .center_y()
                    .child(copy_button(
                        "copy-saml-metadata",
                        "Copy metadata URL",
                        metadata.clone(),
                        ui,
                    ))
                    .child(
                        Button::new("Open metadata")
                            .variant(ButtonVariant::Ghost)
                            .on_press_tx(move |s: &mut Workspace, tx: &mut Tx| {
                                open(s, tx, &metadata)
                            })
                            .build(k)
                            .key("saml-download-metadata"),
                    )
                    .child(
                        Button::new("Open sign-in in browser")
                            .variant(ButtonVariant::Ghost)
                            .on_press_tx(move |s: &mut Workspace, tx: &mut Tx| {
                                open(s, tx, &sign_in)
                            })
                            .build(k)
                            .key("saml-open-sign-in"),
                    ),
            );
        }
        match self.saml.inspections.first() {
            Some(inspection) => body.child(saml_response(inspection, 0, ui)),
            None => body.child(empty(
                "Run a sign-in to inspect the signed SAML response.",
                ui,
            )),
        }
    }

    fn saml_history(&self, ui: &Ui) -> El {
        let mut body = col().w_full().gap(16.0);
        for (index, entry) in self.saml.inspections.iter().enumerate() {
            body = body.child(saml_response(entry, index, ui));
        }
        if self.saml.inspections.is_empty() {
            body = body.child(empty("No SAML flows have been inspected yet.", ui));
        }
        body
    }

    fn saml_sessions(&self, ui: &Ui) -> El {
        let p = ui.p;
        let k = &ui.k;
        let mut body = col().w_full().gap(12.0).child(
            row()
                .gap(8.0)
                .child(
                    Button::new("Refresh")
                        .disabled(self.busy)
                        .on_press(|s: &mut Workspace| s.refresh_identity())
                        .build(k)
                        .key("saml-refresh"),
                )
                .child(
                    Button::new("End all sessions")
                        .disabled(self.busy)
                        .on_press(|s: &mut Workspace| {
                            s.identity_command(|identity, id| {
                                Ok(format!(
                                    "Ended {} sessions",
                                    identity.end_sessions(&id, "")?
                                ))
                            })
                        })
                        .build(k)
                        .key("saml-end-all"),
                ),
        );
        let sessions = self
            .oidc
            .sessions
            .iter()
            .filter(|session| session.get("saml_session_index").is_some())
            .collect::<Vec<_>>();
        for (index, session) in sessions.iter().enumerate() {
            let id = text(session, "session_id");
            let redirect_id = id.clone();
            let post_id = id.clone();
            body = body.child(
                col()
                    .key(format!("saml-session-{index}"))
                    .role("group")
                    .label(format!(
                        "SAML session for {}: {}. Name ID {}. Session index {}",
                        text(session, "user"),
                        text(session, "authn_strength"),
                        text(session, "saml_name_id"),
                        text(session, "saml_session_index")
                    ))
                    .w_full()
                    .gap(8.0)
                    .padding(16.0)
                    .radius(6.0)
                    .fill(p.card)
                    .child(font_text(
                        format!(
                            "{} · {}",
                            text(session, "user"),
                            text(session, "authn_strength")
                        ),
                        13.0,
                        SEMIBOLD,
                        p.text,
                        ui,
                    ))
                    .child(
                        font_text(
                            format!(
                                "{} · {}",
                                text(session, "saml_name_id"),
                                text(session, "saml_session_index")
                            ),
                            13.0,
                            400.0,
                            p.muted,
                            ui,
                        )
                        .wrap_anywhere(),
                    )
                    .child(
                        row()
                            .gap(8.0)
                            .child(
                                Button::new("Log out via Redirect")
                                    .disabled(self.busy)
                                    .on_press(move |s: &mut Workspace| {
                                        s.saml_browser_logout(redirect_id.clone(), "redirect")
                                    })
                                    .build(k)
                                    .key(format!("saml-logout-redirect-{index}")),
                            )
                            .child(
                                Button::new("Log out via POST")
                                    .disabled(self.busy)
                                    .on_press(move |s: &mut Workspace| {
                                        s.saml_browser_logout(post_id.clone(), "post")
                                    })
                                    .build(k)
                                    .key(format!("saml-logout-post-{index}")),
                            )
                            .child(
                                Button::new("End locally")
                                    .variant(ButtonVariant::Ghost)
                                    .disabled(self.busy)
                                    .on_press(move |s: &mut Workspace| {
                                        let id = id.clone();
                                        s.identity_command(move |identity, environment| {
                                            Ok(format!(
                                                "Ended {} sessions",
                                                identity.end_sessions(&environment, &id)?
                                            ))
                                        });
                                    })
                                    .build(k)
                                    .key(format!("saml-end-session-{index}")),
                            ),
                    ),
            );
        }
        if sessions.is_empty() {
            body = body.child(empty("No live sessions with a SAML sign-in.", ui));
        }
        body = body.child(font_text("Logout results", 13.0, SEMIBOLD, p.text, ui).pt(12.0));
        for (index, entry) in self.saml.logouts.iter().enumerate() {
            let detail = text(entry, "detail");
            let mut card = col()
                .key(format!("saml-logout-{index}"))
                .role("group")
                .label(format!(
                    "Logout for {} via {}: {}. {}. {}",
                    text(entry, "user"),
                    text(entry, "binding"),
                    text(entry, "outcome"),
                    text(entry, "destination"),
                    detail
                ))
                .w_full()
                .gap(8.0)
                .padding(16.0)
                .radius(6.0)
                .fill(p.card)
                .child(
                    row()
                        .w_full()
                        .gap(12.0)
                        .center_y()
                        .child(
                            font_text(
                                format!("{} · {}", text(entry, "user"), text(entry, "binding")),
                                13.0,
                                SEMIBOLD,
                                p.text,
                                ui,
                            )
                            .grow(1.0)
                            .min_w(0.0),
                        )
                        .child(font_text(
                            text(entry, "outcome"),
                            13.0,
                            400.0,
                            if entry["outcome"] == "failed" {
                                p.danger
                            } else {
                                p.muted
                            },
                            ui,
                        )),
                )
                .child(
                    font_text(text(entry, "destination"), 13.0, 400.0, p.text, ui).wrap_anywhere(),
                );
            if !detail.is_empty() {
                card = card.child(font_text(detail, 13.0, 400.0, p.text, ui).wrap());
            }
            body = body.child(card);
        }
        if self.saml.logouts.is_empty() {
            body = body.child(empty("No logout requests have been sent.", ui));
        }
        body
    }
}

fn saml_response(entry: &Value, index: usize, ui: &Ui) -> El {
    let p = ui.p;
    let xml = text(entry, "ResponseXML");
    let faults = text(entry, "Faults");
    let muted =
        |value: String| -> El { font_text(value, 13.0, 400.0, p.muted, ui).wrap_anywhere() };
    let mut body = col()
        .key(format!("saml-response-{index}"))
        .role("group")
        .label(format!(
            "SAML response for {}. ACS {}. Assertion {}. Request {}. {}",
            text(entry, "User"),
            text(entry, "ACSURL"),
            text(entry, "AssertionID"),
            text(entry, "InResponseTo"),
            text(entry, "UpdatedAt")
        ))
        .w_full()
        .gap(12.0)
        .padding(16.0)
        .radius(6.0)
        .border(1.0, p.line)
        .fill(p.card)
        .child(
            row()
                .w_full()
                .gap(12.0)
                .center_y()
                .child(
                    font_text(
                        format!("{} · {}", text(entry, "User"), text(entry, "UpdatedAt")),
                        13.0,
                        SEMIBOLD,
                        p.text,
                        ui,
                    )
                    .grow(1.0)
                    .min_w(0.0)
                    .wrap(),
                )
                .child(copy_button(
                    format!("copy-saml-xml-{index}"),
                    "Copy XML",
                    xml.clone(),
                    ui,
                ))
                .child(copy_button(
                    format!("copy-saml-base64-{index}"),
                    "Copy Base64",
                    text(entry, "EncodedResponse"),
                    ui,
                )),
        )
        .child(muted(format!("ACS: {}", text(entry, "ACSURL"))))
        .child(muted(format!(
            "Assertion: {} · Request: {}",
            text(entry, "AssertionID"),
            text(entry, "InResponseTo")
        )));
    if !faults.is_empty() {
        body = body.child(
            font_text(faults, 13.0, 400.0, p.danger, ui)
                .key("faults")
                .wrap(),
        );
    }
    body = body.child(xml_panel("SAML response", &xml, ui));
    let plaintext = text(entry, "PlaintextAssertionXML");
    if !plaintext.is_empty() {
        body = body
            .child(copy_button(
                format!("copy-plaintext-assertion-{index}"),
                "Copy plaintext assertion",
                plaintext.clone(),
                ui,
            ))
            .child(xml_panel("Assertion before encryption", &plaintext, ui));
    }
    body
}

fn xml_panel(title: &str, xml: &str, ui: &Ui) -> El {
    code_panel(title, xml.replace("><", ">\n<"), 11.0, ui)
}
