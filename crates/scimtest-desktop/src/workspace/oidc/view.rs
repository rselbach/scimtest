use super::{Workspace, fault};
use crate::dropdown::DropdownMenu;
use crate::theme::Palette;
use crate::workspace::view::accessible_text;
use gpui::{ClipboardItem, Context, Div, div, prelude::*, px};
use gpui_component::{
    Disableable, Selectable, StyledExt,
    button::{Button, ButtonVariants},
    menu::PopupMenuItem,
    scroll::ScrollableElement,
};
use serde_json::Value;

impl Workspace {
    pub(crate) fn oidc_inspector(&self, cx: &mut Context<Self>) -> Div {
        let palette = Palette::get(cx);
        let selected = if self.oidc.section.is_empty() {
            "Playground"
        } else {
            self.oidc.section
        };
        let mut tabs = div().h_flex().gap_2().pb_4();
        for section in [
            "Playground",
            "Tokens & sessions",
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
                        view.oidc.section = section;
                        cx.notify();
                    })),
            );
        }
        let body = match selected {
            "Tokens & sessions" => self.session_controls(cx),
            "Inspections" => self.inspection_history(cx),
            "Flow activity" => self.flow_activity(cx),
            "Signing keys" => self.signing_controls(cx),
            _ => self.playground_controls(cx),
        };
        div().v_flex().flex_1().min_h_0().child(tabs).child(
            div()
                .id("oidc-scroll")
                .flex_1()
                .min_h_0()
                .overflow_y_scrollbar()
                .child(body),
        )
    }
    fn playground_controls(&self, cx: &mut Context<Self>) -> Div {
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
            .find(|user| self.oidc.user == user.id)
            .or_else(|| users.first());
        let label = user
            .map(|user| format!("{} {}", user.fields.given_name, user.fields.family_name))
            .unwrap_or_else(|| "Choose account".into());
        let view = cx.weak_entity();
        let picker = Button::new("oidc-account")
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
                                view.oidc.user = id.clone();
                                cx.notify();
                            });
                        }),
                    );
                }
                menu
            });
        let view = cx.weak_entity();
        let fault_picker = Button::new("oidc-fault")
            .label(if self.oidc.fault.is_empty() {
                "Healthy sign-in"
            } else {
                self.oidc.fault
            })
            .disabled(self.busy)
            .dropdown_menu(move |mut menu, _, _| {
                for label in [
                    "Healthy sign-in",
                    "Expired ID token",
                    "Broken signature",
                    "Missing email",
                    "Wrong audience",
                    "Unsigned token",
                    "Token endpoint error",
                ] {
                    let view = view.clone();
                    menu = menu.item(PopupMenuItem::new(label).on_click(move |_, _, cx| {
                        let _ = view.update(cx, |view, cx| {
                            view.oidc.fault = if label == "Healthy sign-in" {
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
        let mut body = div().v_flex().gap_4().child(
            div()
                .h_flex()
                .gap_2()
                .child(picker)
                .child(fault_picker)
                .child(
                    Button::new("oidc-refresh-toggle")
                        .label(if self.oidc.refresh {
                            "Refresh test: on"
                        } else {
                            "Refresh test: off"
                        })
                        .disabled(self.busy)
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.oidc.refresh = !view.oidc.refresh;
                            cx.notify();
                        })),
                ),
        );
        if let Some(directory) = self.directory() {
            let url = format!(
                "{}/inspect/oidc/{}/playground",
                self.api_url, directory.environment.slug
            );
            body = body.child(
                Button::new("oidc-browser-playground")
                    .label("Open browser playground")
                    .on_click(move |_, _, cx| cx.open_url(&url)),
            );
        }
        if let Some(result) = &self.oidc.result {
            body = body.child(
                div()
                    .h_flex()
                    .gap_3()
                    .child(div().flex_1().child(format!(
                            "Authorize {}   ·   Token {}   ·   Userinfo {}{}",
                            result["authorize_status"],
                            result["token_status"],
                            result["userinfo_status"],
                            result
                                .get("refresh_status")
                                .map(|status| format!("   ·   Refresh {status}"))
                                .unwrap_or_default()
                        )))
                    .child(copy_button(
                        "copy-oidc-result",
                        "Copy full result",
                        serde_json::to_string_pretty(result).unwrap_or_default(),
                        cx,
                    )),
            );
            body = body
                .child(json_panel(
                    "ID token header",
                    &result["id_token_header"],
                    cx,
                ))
                .child(json_panel(
                    "ID token claims",
                    &result["id_token_claims"],
                    cx,
                ))
                .child(json_panel("Userinfo", &result["userinfo"], cx));
            if let Some(claims) = result.get("refreshed_id_token_claims") {
                body = body.child(json_panel("Refreshed ID token claims", claims, cx));
            }
            if let Some(claims) = result.get("access_token_claims") {
                body = body.child(json_panel("Access token claims", claims, cx));
            }
        } else {
            body = body.child(empty("Run a sign-in to inspect tokens and claims.", cx));
        }
        body
    }
    fn session_controls(&self, cx: &mut Context<Self>) -> Div {
        let palette = Palette::get(cx);
        let mut body = div()
            .v_flex()
            .gap_3()
            .child(
                div()
                    .h_flex()
                    .gap_2()
                    .child(
                        Button::new("oidc-reload")
                            .label("Refresh")
                            .disabled(self.busy)
                            .on_click(cx.listener(|view, _, _, cx| view.refresh_identity(cx))),
                    )
                    .child(
                        Button::new("oidc-revoke-all")
                            .label("Revoke all tokens")
                            .disabled(self.busy)
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.identity_command(
                                    |identity, id| {
                                        Ok(format!(
                                            "Revoked {} tokens",
                                            identity.revoke_tokens(&id, "")?
                                        ))
                                    },
                                    cx,
                                )
                            })),
                    )
                    .child(
                        Button::new("oidc-end-all")
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
                                )
                            })),
                    ),
            )
            .child(
                div()
                    .pt_3()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("Token holders"),
            );
        for (index, holder) in self.oidc.holders.iter().enumerate() {
            let user = text(holder, "user_id");
            body = body.child(
                div()
                    .id(("token-holder", index))
                    .role(gpui::Role::Group)
                    .aria_label(format!(
                        "{}: {} access tokens, {} refresh tokens",
                        text(holder, "user"),
                        holder["access_tokens"],
                        holder["refresh_tokens"]
                    ))
                    .h_flex()
                    .gap_3()
                    .p_3()
                    .bg(palette.card)
                    .rounded_md()
                    .child(div().flex_1().child(format!(
                        "{}   ·   {} access   ·   {} refresh",
                        text(holder, "user"),
                        holder["access_tokens"],
                        holder["refresh_tokens"]
                    )))
                    .child(
                        Button::new(("revoke-user", index))
                            .accessibility_label(format!(
                                "Revoke tokens for {}",
                                text(holder, "user")
                            ))
                            .label("Revoke")
                            .ghost()
                            .disabled(self.busy)
                            .on_click(cx.listener(move |view, _, _, cx| {
                                let user = user.clone();
                                view.identity_command(
                                    move |identity, id| {
                                        Ok(format!(
                                            "Revoked {} tokens",
                                            identity.revoke_tokens(&id, &user)?
                                        ))
                                    },
                                    cx,
                                );
                            })),
                    ),
            );
        }
        if self.oidc.holders.is_empty() {
            body = body.child(empty("No live user tokens.", cx));
        }
        body = body.child(
            div()
                .pt_3()
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child("Browser sessions"),
        );
        for (index, session) in self.oidc.sessions.iter().enumerate() {
            let id = text(session, "session_id");
            body = body.child(
                div()
                    .id(("browser-session", index))
                    .role(gpui::Role::Group)
                    .aria_label(format!(
                        "{}: {}. Signed in {}",
                        text(session, "user"),
                        text(session, "authn_strength"),
                        text(session, "signed_in_at")
                    ))
                    .h_flex()
                    .gap_3()
                    .p_3()
                    .bg(palette.card)
                    .rounded_md()
                    .child(div().flex_1().child(format!(
                        "{}   ·   {}   ·   {}",
                        text(session, "user"),
                        text(session, "authn_strength"),
                        text(session, "signed_in_at")
                    )))
                    .child(
                        Button::new(("end-session", index))
                            .accessibility_label(format!(
                                "End session for {}",
                                text(session, "user")
                            ))
                            .label("End session")
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
            );
        }
        if self.oidc.sessions.is_empty() {
            body = body.child(empty("No live browser sessions.", cx));
        }
        body
    }
    fn inspection_history(&self, cx: &mut Context<Self>) -> Div {
        let palette = Palette::get(cx);
        let mut body = div().v_flex().gap_4();
        for (index, entry) in self.oidc.inspections.iter().enumerate() {
            let token = text(entry, "IDToken");
            let claims = serde_json::from_str(&text(entry, "Claims")).unwrap_or(Value::Null);
            body = body.child(
                div()
                    .id(("oidc-inspection", index))
                    .role(gpui::Role::Group)
                    .aria_label(format!(
                        "{} for {}. Client {}. Scope {}. {}",
                        text(entry, "Stage"),
                        text(entry, "User"),
                        text(entry, "ClientID"),
                        text(entry, "Scope"),
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
                                        text(entry, "Stage"),
                                        text(entry, "User")
                                    )),
                            )
                            .child(copy_button(
                                ("copy-token", index),
                                "Copy ID token",
                                token,
                                cx,
                            )),
                    )
                    .child(div().text_color(palette.muted).child(format!(
                        "{}   ·   {}   ·   {}",
                        text(entry, "ClientID"),
                        text(entry, "Scope"),
                        text(entry, "UpdatedAt")
                    )))
                    .when(!text(entry, "Faults").is_empty(), |panel| {
                        panel.child(
                            div()
                                .text_color(palette.danger)
                                .child(accessible_text("faults", text(entry, "Faults"))),
                        )
                    })
                    .when(!claims.is_null(), |panel| {
                        panel.child(json_panel("Claims", &claims, cx))
                    }),
            );
        }
        if self.oidc.inspections.is_empty() {
            body = body.child(empty("No OIDC flows have been inspected yet.", cx));
        }
        body
    }
    pub(in crate::workspace) fn flow_activity(&self, cx: &mut Context<Self>) -> Div {
        let palette = Palette::get(cx);
        let mut body = div().v_flex().gap_3();
        for (index, event) in self.oidc.flows.iter().enumerate() {
            body =
                body.child(
                    div()
                        .id(("oidc-flow", index))
                        .role(gpui::Role::Group)
                        .aria_label(format!(
                            "{} for {}: {}. {}. {}",
                            text(event, "Stage"),
                            text(event, "User"),
                            text(event, "Outcome"),
                            text(event, "Time"),
                            text(event, "Detail")
                        ))
                        .v_flex()
                        .gap_2()
                        .p_4()
                        .border_1()
                        .border_color(palette.line)
                        .rounded_md()
                        .bg(palette.card)
                        .child(
                            div()
                                .h_flex()
                                .gap_3()
                                .child(div().font_weight(gpui::FontWeight::SEMIBOLD).child(
                                    format!("{} · {}", text(event, "Stage"), text(event, "User")),
                                ))
                                .child(
                                    div()
                                        .text_color(if event["Outcome"] == "ok" {
                                            palette.success
                                        } else {
                                            palette.danger
                                        })
                                        .child(text(event, "Outcome")),
                                )
                                .child(div().flex_1())
                                .child(div().text_color(palette.muted).child(text(event, "Time"))),
                        )
                        .child(text(event, "Detail")),
                );
        }
        if self.oidc.flows.is_empty() {
            body = body.child(empty("No flow activity yet.", cx));
        }
        body
    }
    pub(in crate::workspace) fn signing_controls(&self, cx: &mut Context<Self>) -> Div {
        let palette = Palette::get(cx);
        let view = cx.weak_entity();
        let rotate = Button::new("rotate-key")
            .label("Rotate signing key")
            .disabled(self.busy)
            .dropdown_menu(move |mut menu, _, _| {
                for (label, validity, grace) in [
                    ("Standard certificate · 24 hour grace", "standard", "24h"),
                    ("Standard certificate · no grace", "standard", "0s"),
                    ("Expired certificate", "expired", "24h"),
                    ("Not yet valid certificate", "not_yet_valid", "24h"),
                    ("No expiration", "no_expiration", "24h"),
                    ("Zero validity", "zero_time", "24h"),
                ] {
                    let view = view.clone();
                    menu = menu.item(PopupMenuItem::new(label).on_click(move |_, _, cx| {
                        let _ = view.update(cx, |view, cx| {
                            let store = view.store.clone();
                            view.identity_command(
                                move |_, id| {
                                    store.rotate_signing_key(
                                        &id,
                                        scimtest_core::signing::parse_grace(grace)?,
                                        scimtest_core::signing::CertificateValidity::parse(
                                            validity,
                                        )?,
                                    )?;
                                    Ok("Signing key rotated".into())
                                },
                                cx,
                            );
                        });
                    }));
                }
                menu
            });
        let selected_fault = self.oidc.fault;
        let selected_faults = if self.tab == crate::workspace::Tab::Saml {
            crate::workspace::saml::fault(self.saml.fault)
        } else {
            fault(selected_fault)
        };
        let mut body = div().v_flex().gap_3().child(div().h_flex().gap_2().child(rotate)
            .child(Button::new("arm-fault").label("Arm selected fault for next sign-in").disabled(self.busy || selected_faults.is_none())
                .on_click(cx.listener(move |view,_,_,cx| { if let Some(faults) = selected_faults.clone() { view.identity_command(move |identity,id| { identity.arm_faults(&id,faults)?;Ok("Fault armed for the next sign-in".into()) },cx); } })))
            .child(Button::new("clear-faults").label("Clear armed faults").disabled(self.busy).on_click(cx.listener(|view,_,_,cx| view.identity_command(|identity,id| { identity.disarm_faults(&id)?;Ok("Armed faults cleared".into()) },cx)))))
            .child(empty("Retired keys stay published during their grace period. Certificate presets let you test validation failures.",cx));
        for (index, key) in self.oidc.keys.iter().enumerate() {
            body = body.child(
                div()
                    .id(gpui::SharedString::from(key.kid.clone()))
                    .role(gpui::Role::Group)
                    .aria_label(format!(
                        "Signing key {}: {}. Valid from {} to {}. Published until {}",
                        key.kid,
                        if key.active { "Active" } else { "Retired" },
                        key.not_before,
                        key.not_after,
                        key.published_until
                            .as_deref()
                            .unwrap_or("no retirement scheduled")
                    ))
                    .v_flex()
                    .gap_2()
                    .p_4()
                    .bg(palette.card)
                    .border_1()
                    .border_color(palette.line)
                    .rounded_md()
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
                                        key.kid,
                                        if key.active { "Active" } else { "Retired" }
                                    )),
                            )
                            .child(copy_button(
                                ("copy-certificate", index),
                                "Copy certificate",
                                key.certificate_pem.clone(),
                                cx,
                            )),
                    )
                    .child(format!(
                        "Valid from {} to {}",
                        key.not_before, key.not_after
                    ))
                    .when_some(key.published_until.clone(), |panel, until| {
                        panel.child(
                            div()
                                .text_color(palette.muted)
                                .child(format!("Published until {until}")),
                        )
                    }),
            );
        }
        body
    }
}
pub(in crate::workspace) fn text(value: &Value, name: &str) -> String {
    value[name].as_str().unwrap_or_default().into()
}
pub(in crate::workspace) fn empty(message: &str, cx: &Context<Workspace>) -> Div {
    div()
        .py_3()
        .text_color(Palette::get(cx).muted)
        .child(accessible_text(
            gpui::SharedString::from(message.to_owned()),
            message.to_owned(),
        ))
}
pub(in crate::workspace) fn copy_button(
    id: impl Into<gpui::ElementId>,
    label: &'static str,
    value: String,
    cx: &mut Context<Workspace>,
) -> Button {
    Button::new(id)
        .label(label)
        .ghost()
        .on_click(cx.listener(move |_, _, _, cx| {
            cx.write_to_clipboard(ClipboardItem::new_string(value.clone()))
        }))
}
fn json_panel(title: &str, value: &Value, cx: &Context<Workspace>) -> gpui::Stateful<Div> {
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
                .p_4()
                .rounded_md()
                .border_1()
                .border_color(palette.line)
                .bg(palette.card)
                .font_family("monospace")
                .text_size(px(12.))
                .child(accessible_text(
                    "payload",
                    serde_json::to_string_pretty(value).unwrap_or_default(),
                )),
        )
}
