use super::{Workspace, fault};
use crate::dropdown::DropdownMenu;
use crate::workspace::view::accessible_text;
use crate::{
    theme::Palette,
    workspace::oidc::view::{copy_button, empty, text},
};
use gpui::{Context, Div, div, prelude::*, px};
use gpui_component::{
    Disableable, Selectable, StyledExt,
    button::{Button, ButtonVariants},
    menu::PopupMenuItem,
    scroll::ScrollableElement,
};

impl Workspace {
    pub(in crate::workspace) fn saml_inspector(&self, cx: &mut Context<Self>) -> Div {
        let palette = Palette::get(cx);
        let selected = if self.saml.section.is_empty() {
            "Sign-in"
        } else {
            self.saml.section
        };
        let mut tabs = div().h_flex().gap_2().pb_4();
        for section in [
            "Sign-in",
            "Sessions & logout",
            "Inspections",
            "Flow activity",
            "Signing keys",
        ] {
            tabs = tabs.child(
                Button::new(section)
                    .label(section)
                    .selected(selected == section)
                    .toggled(selected == section)
                    .ghost()
                    .when(selected == section, |button| {
                        button.bg(palette.selected).text_color(palette.accent)
                    })
                    .on_click(cx.listener(move |view, _, _, cx| {
                        view.saml.section = section;
                        cx.notify();
                    })),
            );
        }
        let body = match selected {
            "Sessions & logout" => self.saml_sessions(cx),
            "Inspections" => self.saml_history(cx),
            "Flow activity" => self.flow_activity(cx),
            "Signing keys" => self.signing_controls(cx),
            _ => self.saml_sign_in(cx),
        };
        div().v_flex().flex_1().min_h_0().child(tabs).child(
            div()
                .id("saml-scroll")
                .flex_1()
                .min_h_0()
                .overflow_y_scrollbar()
                .child(body),
        )
    }
    fn saml_sign_in(&self, cx: &mut Context<Self>) -> Div {
        let users = self
            .directory()
            .map(|directory| {
                directory
                    .projected_users()
                    .into_iter()
                    .filter(|user| user.fields.active && !user.deleted)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let user = users
            .iter()
            .find(|user| user.id == self.saml.user)
            .or_else(|| users.first());
        let label = user
            .map(|user| format!("{} {}", user.fields.given_name, user.fields.family_name))
            .unwrap_or_else(|| "Choose account".into());
        let view = cx.weak_entity();
        let picker = Button::new("saml-account")
            .label(label)
            .disabled(self.busy)
            .dropdown_menu(move |mut menu, _, _| {
                for user in &users {
                    let id = user.id.clone();
                    let view = view.clone();
                    menu = menu.item(
                        PopupMenuItem::new(format!(
                            "{} {} · {}",
                            user.fields.given_name, user.fields.family_name, user.fields.email
                        ))
                        .on_click(move |_, _, cx| {
                            let _ = view.update(cx, |view, cx| {
                                view.saml.user = id.clone();
                                cx.notify();
                            });
                        }),
                    );
                }
                menu
            });
        let view = cx.weak_entity();
        let fault_picker = Button::new("saml-fault")
            .label(if self.saml.fault.is_empty() {
                "Healthy sign-in"
            } else {
                self.saml.fault
            })
            .disabled(self.busy)
            .dropdown_menu(move |mut menu, _, _| {
                for label in [
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
                ] {
                    let view = view.clone();
                    menu = menu.item(PopupMenuItem::new(label).on_click(move |_, _, cx| {
                        let _ = view.update(cx, |view, cx| {
                            view.saml.fault = if label == "Healthy sign-in" {
                                ""
                            } else {
                                label
                            };
                            cx.notify();
                        });
                    }));
                }
                menu
            });
        let selected_fault = fault(self.saml.fault);
        let mut body = div().v_flex().gap_4().child(
            div()
                .h_flex()
                .gap_2()
                .flex_wrap()
                .child(picker)
                .child(fault_picker)
                .child(
                    Button::new("saml-strength")
                        .label(if self.saml.mfa { "MFA" } else { "Password" })
                        .disabled(self.busy)
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.saml.mfa = !view.saml.mfa;
                            cx.notify();
                        })),
                )
                .child(
                    Button::new("saml-arm-fault")
                        .label("Arm fault")
                        .disabled(self.busy || selected_fault.is_none())
                        .on_click(cx.listener(move |view, _, _, cx| {
                            if let Some(faults) = selected_fault.clone() {
                                view.identity_command(
                                    move |identity, id| {
                                        identity.arm_faults(&id, faults)?;
                                        Ok("Fault armed for the next sign-in".into())
                                    },
                                    cx,
                                );
                            }
                        })),
                ),
        );
        if let Some(directory) = self.directory() {
            let metadata = format!(
                "{}/saml/{}/metadata",
                self.api_url, directory.environment.slug
            );
            let sign_in = format!("{}/saml/{}/sso", self.api_url, directory.environment.slug);
            body = body.child(
                div()
                    .h_flex()
                    .gap_2()
                    .child(copy_button(
                        "copy-saml-metadata",
                        "Copy metadata URL",
                        metadata.clone(),
                        cx,
                    ))
                    .child(
                        Button::new("saml-download-metadata")
                            .label("Open metadata")
                            .ghost()
                            .on_click(cx.listener(move |_, _, _, cx| cx.open_url(&metadata))),
                    )
                    .child(
                        Button::new("saml-open-sign-in")
                            .label("Open sign-in in browser")
                            .ghost()
                            .on_click(cx.listener(move |_, _, _, cx| cx.open_url(&sign_in))),
                    ),
            );
        }
        if let Some(inspection) = self.saml.inspections.first() {
            body = body.child(self.saml_response(inspection, 0, cx));
        } else {
            body = body.child(empty(
                "Run a sign-in to inspect the signed SAML response.",
                cx,
            ));
        }
        body
    }
    fn saml_response(
        &self,
        entry: &serde_json::Value,
        index: usize,
        cx: &mut Context<Self>,
    ) -> gpui::Stateful<Div> {
        let palette = Palette::get(cx);
        let xml = text(entry, "ResponseXML");
        let mut body = div()
            .id(("saml-response", index))
            .role(gpui::Role::Group)
            .aria_label(format!(
                "SAML response for {}. ACS {}. Assertion {}. Request {}. {}",
                text(entry, "User"),
                text(entry, "ACSURL"),
                text(entry, "AssertionID"),
                text(entry, "InResponseTo"),
                text(entry, "UpdatedAt")
            ))
            .v_flex()
            .gap_3()
            .p_4()
            .border_1()
            .border_color(palette.line)
            .rounded_md()
            .bg(palette.card)
            .child(
                div()
                    .h_flex()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(format!(
                                "{} · {}",
                                text(entry, "User"),
                                text(entry, "UpdatedAt")
                            )),
                    )
                    .child(copy_button(
                        ("copy-saml-xml", index),
                        "Copy XML",
                        xml.clone(),
                        cx,
                    ))
                    .child(copy_button(
                        ("copy-saml-base64", index),
                        "Copy Base64",
                        text(entry, "EncodedResponse"),
                        cx,
                    )),
            )
            .child(
                div()
                    .text_color(palette.muted)
                    .child(format!("ACS: {}", text(entry, "ACSURL"))),
            )
            .child(div().text_color(palette.muted).child(format!(
                "Assertion: {} · Request: {}",
                text(entry, "AssertionID"),
                text(entry, "InResponseTo")
            )))
            .when(!text(entry, "Faults").is_empty(), |panel| {
                panel.child(
                    div()
                        .text_color(palette.danger)
                        .child(accessible_text("faults", text(entry, "Faults"))),
                )
            })
            .child(xml_panel("SAML response", &xml, cx));
        let plaintext = text(entry, "PlaintextAssertionXML");
        if !plaintext.is_empty() {
            body = body
                .child(copy_button(
                    ("copy-plaintext-assertion", index),
                    "Copy plaintext assertion",
                    plaintext.clone(),
                    cx,
                ))
                .child(xml_panel("Assertion before encryption", &plaintext, cx));
        }
        body
    }
    fn saml_history(&self, cx: &mut Context<Self>) -> Div {
        let mut body = div().v_flex().gap_4();
        for (index, entry) in self.saml.inspections.iter().enumerate() {
            body = body.child(self.saml_response(entry, index, cx));
        }
        if self.saml.inspections.is_empty() {
            body = body.child(empty("No SAML flows have been inspected yet.", cx));
        }
        body
    }
    fn saml_sessions(&self, cx: &mut Context<Self>) -> Div {
        let palette = Palette::get(cx);
        let mut body = div().v_flex().gap_3().child(
            div()
                .h_flex()
                .gap_2()
                .child(
                    Button::new("saml-refresh")
                        .label("Refresh")
                        .disabled(self.busy)
                        .on_click(cx.listener(|view, _, _, cx| view.refresh_identity(cx))),
                )
                .child(
                    Button::new("saml-end-all")
                        .label("End all sessions")
                        .disabled(self.busy)
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.identity_command(
                                |identity, id| {
                                    Ok(format!(
                                        "Ended {} sessions",
                                        identity.end_sessions(&id, "")?
                                    ))
                                },
                                cx,
                            );
                        })),
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
                div()
                    .id(("saml-session", index))
                    .role(gpui::Role::Group)
                    .aria_label(format!(
                        "SAML session for {}: {}. Name ID {}. Session index {}",
                        text(session, "user"),
                        text(session, "authn_strength"),
                        text(session, "saml_name_id"),
                        text(session, "saml_session_index")
                    ))
                    .v_flex()
                    .gap_2()
                    .p_4()
                    .rounded_md()
                    .bg(palette.card)
                    .child(div().font_weight(gpui::FontWeight::SEMIBOLD).child(format!(
                        "{} · {}",
                        text(session, "user"),
                        text(session, "authn_strength")
                    )))
                    .child(div().text_color(palette.muted).child(format!(
                        "{} · {}",
                        text(session, "saml_name_id"),
                        text(session, "saml_session_index")
                    )))
                    .child(
                        div()
                            .h_flex()
                            .gap_2()
                            .child(
                                Button::new(("saml-logout-redirect", index))
                                    .label("Log out via Redirect")
                                    .disabled(self.busy)
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.saml_browser_logout(
                                            redirect_id.clone(),
                                            "redirect",
                                            cx,
                                        )
                                    })),
                            )
                            .child(
                                Button::new(("saml-logout-post", index))
                                    .label("Log out via POST")
                                    .disabled(self.busy)
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.saml_browser_logout(post_id.clone(), "post", cx)
                                    })),
                            )
                            .child(
                                Button::new(("saml-end-session", index))
                                    .label("End locally")
                                    .ghost()
                                    .disabled(self.busy)
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        let id = id.clone();
                                        view.identity_command(
                                            move |identity, environment| {
                                                Ok(format!(
                                                    "Ended {} sessions",
                                                    identity.end_sessions(&environment, &id)?
                                                ))
                                            },
                                            cx,
                                        );
                                    })),
                            ),
                    ),
            );
        }
        if sessions.is_empty() {
            body = body.child(empty("No live sessions with a SAML sign-in.", cx));
        }
        body = body.child(
            div()
                .pt_3()
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child("Logout results"),
        );
        for (index, entry) in self.saml.logouts.iter().enumerate() {
            body = body.child(
                div()
                    .id(("saml-logout", index))
                    .role(gpui::Role::Group)
                    .aria_label(format!(
                        "Logout for {} via {}: {}. {}. {}",
                        text(entry, "user"),
                        text(entry, "binding"),
                        text(entry, "outcome"),
                        text(entry, "destination"),
                        text(entry, "detail")
                    ))
                    .v_flex()
                    .gap_2()
                    .p_4()
                    .rounded_md()
                    .bg(palette.card)
                    .child(
                        div()
                            .h_flex()
                            .gap_3()
                            .child(
                                div()
                                    .flex_1()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child(format!(
                                        "{} · {}",
                                        text(entry, "user"),
                                        text(entry, "binding")
                                    )),
                            )
                            .child(
                                div()
                                    .text_color(if entry["outcome"] == "failed" {
                                        palette.danger
                                    } else {
                                        palette.muted
                                    })
                                    .child(text(entry, "outcome")),
                            ),
                    )
                    .child(text(entry, "destination"))
                    .child(text(entry, "detail")),
            );
        }
        if self.saml.logouts.is_empty() {
            body = body.child(empty("No logout requests have been sent.", cx));
        }
        body
    }
}
fn xml_panel(title: &str, xml: &str, cx: &Context<Workspace>) -> gpui::Stateful<Div> {
    let palette = Palette::get(cx);
    div()
        .id(gpui::SharedString::from(title.to_owned()))
        .role(gpui::Role::Group)
        .aria_label(title.to_owned())
        .v_flex()
        .gap_2()
        .child(
            div()
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(title.to_owned()),
        )
        .child(
            div()
                .p_3()
                .rounded_md()
                .border_1()
                .border_color(palette.line)
                .font_family("monospace")
                .text_size(px(11.))
                .child(accessible_text("payload", xml.replace("><", ">\n<"))),
        )
}
