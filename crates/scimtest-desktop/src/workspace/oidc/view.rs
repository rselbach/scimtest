use rune::{El, ScrollSpec, TextStyle, Tx, col, el, row};
use rune_kit::{Button, ButtonVariant};
use serde_json::Value;

use super::{
    super::{
        Tab, Workspace, saml,
        view::{Choice, copy_button, dropdown, empty, font_text},
    },
    fault,
};
use crate::theme::{SEMIBOLD, Ui};

const FAULTS: [&str; 7] = [
    "Healthy sign-in",
    "Expired ID token",
    "Broken signature",
    "Missing email",
    "Wrong audience",
    "Unsigned token",
    "Token endpoint error",
];

impl Workspace {
    pub(in crate::workspace) fn oidc_inspector(&self, ui: &Ui, layer: &mut Vec<El>) -> El {
        let mut body = col()
            .w_full()
            .gap(20.0)
            .child(inspector_card(
                "Latest flow",
                "Run an OIDC sign-in for this environment, then return here to inspect the latest flow.",
                self.playground_controls(ui, layer),
                ui,
            ))
            .child(inspector_card(
                "Signing keys",
                "The JWKS and SAML metadata publish these keys. Rotating signs new tokens and assertions with a new key and keeps the old key published for the grace period.",
                self.signing_controls(ui, layer),
                ui,
            ));
        for (key, label) in [
            ("oidc-sessions", "Tokens & sessions"),
            ("oidc-inspections", "Inspections"),
            ("oidc-flows", "Flow activity"),
        ] {
            body = body.child(self.disclosure(key, label, ui));
            if self.disclosures.contains(key) {
                body = body.child(match key {
                    "oidc-sessions" => self.session_controls(ui),
                    "oidc-inspections" => self.inspection_history(ui),
                    _ => self.flow_activity(ui),
                });
            }
        }
        col()
            .key("oidc-scroll")
            .w_full()
            .min_h(0.0)
            .scroll(ScrollSpec {
                stick_bottom: false,
            })
            .child(body)
    }

    fn playground_controls(&self, ui: &Ui, layer: &mut Vec<El>) -> El {
        let p = ui.p;
        let users = self.active_users();
        let user = users
            .iter()
            .find(|user| self.oidc.user == user.id)
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
                    move |s: &mut Workspace| s.oidc.user = id.clone(),
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
                Choice::new(label, move |s: &mut Workspace| s.oidc.fault = value)
                    .checked(self.oidc.fault == value)
            })
            .collect();
        let mut body = col().w_full().gap(16.0).child(
            row()
                .gap(8.0)
                .center_y()
                .flex_wrap()
                .child(dropdown(
                    self,
                    "oidc-account",
                    label,
                    None,
                    self.busy,
                    accounts,
                    ui,
                    layer,
                ))
                .child(dropdown(
                    self,
                    "oidc-fault",
                    if self.oidc.fault.is_empty() {
                        "Healthy sign-in"
                    } else {
                        self.oidc.fault
                    },
                    None,
                    self.busy,
                    faults,
                    ui,
                    layer,
                ))
                .child(
                    Button::new(if self.oidc.refresh {
                        "Refresh test: on"
                    } else {
                        "Refresh test: off"
                    })
                    .disabled(self.busy)
                    .on_press(|s: &mut Workspace| s.oidc.refresh = !s.oidc.refresh)
                    .build(&ui.k)
                    .key("oidc-refresh-toggle"),
                ),
        );
        if let Some(directory) = self.directory() {
            let url = format!(
                "{}/inspect/oidc/{}/playground",
                self.api_url, directory.environment.slug
            );
            body = body.child(
                row().child(
                    Button::new("Open browser playground")
                        .on_press_tx(move |s: &mut Workspace, tx: &mut Tx| open(s, tx, &url))
                        .build(&ui.k)
                        .key("oidc-browser-playground"),
                ),
            );
        }
        let Some(result) = &self.oidc.result else {
            return body.child(empty("Run a sign-in to inspect tokens and claims.", ui));
        };
        body = body
            .child(
                row()
                    .w_full()
                    .gap(12.0)
                    .center_y()
                    .child(
                        font_text(
                            format!(
                                "Authorize {}   ·   Token {}   ·   Userinfo {}{}",
                                result["authorize_status"],
                                result["token_status"],
                                result["userinfo_status"],
                                result
                                    .get("refresh_status")
                                    .map(|status| format!("   ·   Refresh {status}"))
                                    .unwrap_or_default()
                            ),
                            13.0,
                            400.0,
                            p.text,
                            ui,
                        )
                        .key("oidc-result-statuses")
                        .grow(1.0)
                        .min_w(0.0)
                        .wrap(),
                    )
                    .child(copy_button(
                        "copy-oidc-result",
                        "Copy full result",
                        serde_json::to_string_pretty(result).unwrap_or_default(),
                        ui,
                    )),
            )
            .child(json_panel(
                "ID token header",
                &result["id_token_header"],
                ui,
            ))
            .child(json_panel(
                "ID token claims",
                &result["id_token_claims"],
                ui,
            ))
            .child(json_panel("Userinfo", &result["userinfo"], ui));
        if let Some(claims) = result.get("refreshed_id_token_claims") {
            body = body.child(json_panel("Refreshed ID token claims", claims, ui));
        }
        if let Some(claims) = result.get("access_token_claims") {
            body = body.child(json_panel("Access token claims", claims, ui));
        }
        body
    }

    fn session_controls(&self, ui: &Ui) -> El {
        let p = ui.p;
        let k = &ui.k;
        let mut body = col()
            .w_full()
            .gap(12.0)
            .child(
                row()
                    .gap(8.0)
                    .child(
                        Button::new("Refresh")
                            .disabled(self.busy)
                            .on_press(|s: &mut Workspace| s.refresh_identity())
                            .build(k)
                            .key("oidc-reload"),
                    )
                    .child(
                        Button::new("Revoke all tokens")
                            .disabled(self.busy)
                            .on_press(|s: &mut Workspace| {
                                s.identity_command(|identity, id| {
                                    Ok(format!(
                                        "Revoked {} tokens",
                                        identity.revoke_tokens(&id, "")?
                                    ))
                                })
                            })
                            .build(k)
                            .key("oidc-revoke-all"),
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
                            .key("oidc-end-all"),
                    ),
            )
            .child(font_text("Token holders", 13.0, SEMIBOLD, p.text, ui).pt(12.0));
        for (index, holder) in self.oidc.holders.iter().enumerate() {
            let user = text(holder, "user_id");
            let name = text(holder, "user");
            let summary = format!(
                "{name}   ·   {} access   ·   {} refresh",
                holder["access_tokens"], holder["refresh_tokens"]
            );
            body = body.child(
                row()
                    .key(format!("token-holder-{index}"))
                    .role("group")
                    .label(format!(
                        "{name}: {} access tokens, {} refresh tokens",
                        holder["access_tokens"], holder["refresh_tokens"]
                    ))
                    .w_full()
                    .gap(12.0)
                    .padding(12.0)
                    .center_y()
                    .radius(6.0)
                    .fill(p.card)
                    .child(
                        font_text(summary, 13.0, 400.0, p.text, ui)
                            .grow(1.0)
                            .min_w(0.0)
                            .wrap(),
                    )
                    .child(
                        Button::new("Revoke")
                            .variant(ButtonVariant::Ghost)
                            .disabled(self.busy)
                            .on_press(move |s: &mut Workspace| {
                                let user = user.clone();
                                s.identity_command(move |identity, id| {
                                    Ok(format!(
                                        "Revoked {} tokens",
                                        identity.revoke_tokens(&id, &user)?
                                    ))
                                });
                            })
                            .build(k)
                            .key(format!("revoke-user-{index}"))
                            .label(format!("Revoke tokens for {name}")),
                    ),
            );
        }
        if self.oidc.holders.is_empty() {
            body = body.child(empty("No live user tokens.", ui));
        }
        body = body.child(font_text("Browser sessions", 13.0, SEMIBOLD, p.text, ui).pt(12.0));
        for (index, session) in self.oidc.sessions.iter().enumerate() {
            let id = text(session, "session_id");
            let name = text(session, "user");
            let strength = text(session, "authn_strength");
            let signed_in = text(session, "signed_in_at");
            body = body.child(
                row()
                    .key(format!("browser-session-{index}"))
                    .role("group")
                    .label(format!("{name}: {strength}. Signed in {signed_in}"))
                    .w_full()
                    .gap(12.0)
                    .padding(12.0)
                    .center_y()
                    .radius(6.0)
                    .fill(p.card)
                    .child(
                        font_text(
                            format!("{name}   ·   {strength}   ·   {signed_in}"),
                            13.0,
                            400.0,
                            p.text,
                            ui,
                        )
                        .grow(1.0)
                        .min_w(0.0)
                        .wrap(),
                    )
                    .child(
                        Button::new("End session")
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
                            .key(format!("end-session-{index}"))
                            .label(format!("End session for {name}")),
                    ),
            );
        }
        if self.oidc.sessions.is_empty() {
            body = body.child(empty("No live browser sessions.", ui));
        }
        body
    }

    fn inspection_history(&self, ui: &Ui) -> El {
        let p = ui.p;
        let mut body = col().w_full().gap(16.0);
        for (index, entry) in self.oidc.inspections.iter().enumerate() {
            let claims = serde_json::from_str(&text(entry, "Claims")).unwrap_or(Value::Null);
            let faults = text(entry, "Faults");
            let mut card = col()
                .key(format!("oidc-inspection-{index}"))
                .role("group")
                .label(format!(
                    "{} for {}. Client {}. Scope {}. {}",
                    text(entry, "Stage"),
                    text(entry, "User"),
                    text(entry, "ClientID"),
                    text(entry, "Scope"),
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
                                format!("{} · {}", text(entry, "Stage"), text(entry, "User")),
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
                            format!("copy-token-{index}"),
                            "Copy ID token",
                            text(entry, "IDToken"),
                            ui,
                        )),
                )
                .child(
                    font_text(
                        format!(
                            "{}   ·   {}   ·   {}",
                            text(entry, "ClientID"),
                            text(entry, "Scope"),
                            text(entry, "UpdatedAt")
                        ),
                        13.0,
                        400.0,
                        p.muted,
                        ui,
                    )
                    .wrap(),
                );
            if !faults.is_empty() {
                card = card.child(
                    font_text(faults, 13.0, 400.0, p.danger, ui)
                        .key("faults")
                        .wrap(),
                );
            }
            if !claims.is_null() {
                card = card.child(json_panel("Claims", &claims, ui));
            }
            body = body.child(card);
        }
        if self.oidc.inspections.is_empty() {
            body = body.child(empty("No OIDC flows have been inspected yet.", ui));
        }
        body
    }

    pub(in crate::workspace) fn flow_activity(&self, ui: &Ui) -> El {
        let p = ui.p;
        let mut body = col().w_full().gap(12.0);
        for (index, event) in self.oidc.flows.iter().enumerate() {
            body = body.child(
                col()
                    .key(format!("oidc-flow-{index}"))
                    .role("group")
                    .label(format!(
                        "{} for {}: {}. {}. {}",
                        text(event, "Stage"),
                        text(event, "User"),
                        text(event, "Outcome"),
                        text(event, "Time"),
                        text(event, "Detail")
                    ))
                    .w_full()
                    .gap(8.0)
                    .padding(16.0)
                    .radius(6.0)
                    .border(1.0, p.line)
                    .fill(p.card)
                    .child(
                        row()
                            .w_full()
                            .gap(12.0)
                            .center_y()
                            .child(font_text(
                                format!("{} · {}", text(event, "Stage"), text(event, "User")),
                                13.0,
                                SEMIBOLD,
                                p.text,
                                ui,
                            ))
                            .child(font_text(
                                text(event, "Outcome"),
                                13.0,
                                400.0,
                                if event["Outcome"] == "ok" {
                                    p.success
                                } else {
                                    p.danger
                                },
                                ui,
                            ))
                            .child(el().grow(1.0))
                            .child(font_text(text(event, "Time"), 13.0, 400.0, p.muted, ui)),
                    )
                    .child(font_text(text(event, "Detail"), 13.0, 400.0, p.text, ui).wrap()),
            );
        }
        if self.oidc.flows.is_empty() {
            body = body.child(empty("No flow activity yet.", ui));
        }
        body
    }

    pub(in crate::workspace) fn signing_controls(&self, ui: &Ui, layer: &mut Vec<El>) -> El {
        let p = ui.p;
        let k = &ui.k;
        let rotations = [
            ("Standard certificate · 24 hour grace", "standard", "24h"),
            ("Standard certificate · no grace", "standard", "0s"),
            ("Expired certificate", "expired", "24h"),
            ("Not yet valid certificate", "not_yet_valid", "24h"),
            ("No expiration", "no_expiration", "24h"),
            ("Zero validity", "zero_time", "24h"),
        ]
        .into_iter()
        .map(|(label, validity, grace)| {
            Choice::new(label, move |s: &mut Workspace| {
                let store = s.store.clone();
                s.identity_command(move |_, id| {
                    store.rotate_signing_key(
                        &id,
                        scimtest_core::signing::parse_grace(grace)?,
                        scimtest_core::signing::CertificateValidity::parse(validity)?,
                    )?;
                    Ok("Signing key rotated".into())
                });
            })
        })
        .collect();
        let selected_faults = if self.tab == Tab::Saml {
            saml::fault(self.saml.fault)
        } else {
            fault(self.oidc.fault)
        };
        let mut body = col()
            .w_full()
            .gap(12.0)
            .child(
                row()
                    .gap(8.0)
                    .center_y()
                    .flex_wrap()
                    .child(dropdown(
                        self,
                        "rotate-key",
                        "Rotate signing key",
                        None,
                        self.busy,
                        rotations,
                        ui,
                        layer,
                    ))
                    .child(
                        Button::new("Arm selected fault for next sign-in")
                            .disabled(self.busy || selected_faults.is_none())
                            .on_press(move |s: &mut Workspace| {
                                if let Some(faults) = selected_faults.clone() {
                                    s.identity_command(move |identity, id| {
                                        identity.arm_faults(&id, faults)?;
                                        Ok("Fault armed for the next sign-in".into())
                                    });
                                }
                            })
                            .build(k)
                            .key("arm-fault"),
                    )
                    .child(
                        Button::new("Clear armed faults")
                            .disabled(self.busy)
                            .on_press(|s: &mut Workspace| {
                                s.identity_command(|identity, id| {
                                    identity.disarm_faults(&id)?;
                                    Ok("Armed faults cleared".into())
                                })
                            })
                            .build(k)
                            .key("clear-faults"),
                    ),
            )
            .child(empty(
                "Retired keys stay published during their grace period. Certificate presets let you test validation failures.",
                ui,
            ));
        for (index, key) in self.oidc.keys.iter().enumerate() {
            let state = if key.active { "Active" } else { "Retired" };
            let mut card = col()
                .key(key.kid.clone())
                .role("group")
                .label(format!(
                    "Signing key {}: {state}. Valid from {} to {}. Published until {}",
                    key.kid,
                    key.not_before,
                    key.not_after,
                    key.published_until
                        .as_deref()
                        .unwrap_or("no retirement scheduled")
                ))
                .w_full()
                .gap(8.0)
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
                            font_text(format!("{} · {state}", key.kid), 13.0, SEMIBOLD, p.text, ui)
                                .grow(1.0)
                                .min_w(0.0)
                                .wrap_anywhere(),
                        )
                        .child(copy_button(
                            format!("copy-certificate-{index}"),
                            "Copy certificate",
                            key.certificate_pem.clone(),
                            ui,
                        )),
                )
                .child(font_text(
                    format!("Valid from {} to {}", key.not_before, key.not_after),
                    13.0,
                    400.0,
                    p.text,
                    ui,
                ));
            if let Some(until) = &key.published_until {
                card = card.child(font_text(
                    format!("Published until {until}"),
                    13.0,
                    400.0,
                    p.muted,
                    ui,
                ));
            }
            body = body.child(card);
        }
        body
    }

    /// The selected environment's active users, the accounts a sign-in can run as.
    pub(in crate::workspace) fn active_users(&self) -> Vec<scimtest_core::model::User> {
        self.directory()
            .map(|directory| {
                directory
                    .projected_users()
                    .into_iter()
                    .filter(|user| user.fields.active && !user.deleted)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// The string field `name` of `value`, or nothing.
pub(in crate::workspace) fn text(value: &Value, name: &str) -> String {
    value[name].as_str().unwrap_or_default().into()
}

/// Opens `url` in the browser, reporting a link Rune refuses.
pub(in crate::workspace) fn open(s: &mut Workspace, tx: &mut Tx, url: &str) {
    if let Err(error) = tx.open_url(url) {
        s.fail(error.to_string());
    }
}

/// A titled panel of monospaced text, such as a JSON payload or an XML document.
pub(in crate::workspace) fn code_panel(title: &str, value: String, size: f32, ui: &Ui) -> El {
    let p = ui.p;
    col()
        .key(title.to_owned())
        .role("group")
        .label(title.to_owned())
        .w_full()
        .gap(8.0)
        .child(font_text(title, 13.0, SEMIBOLD, p.text, ui).a11y_hidden())
        .child(
            rune::text(value)
                .key("payload")
                .font(TextStyle {
                    size,
                    ..ui.k.ty.mono
                })
                .color(p.text)
                .w_full()
                .wrap_anywhere()
                .selectable(true)
                .padding(16.0)
                .radius(6.0)
                .border(1.0, p.line)
                .fill(p.card),
        )
}

fn json_panel(title: &str, value: &Value, ui: &Ui) -> El {
    code_panel(
        title,
        serde_json::to_string_pretty(value).unwrap_or_default(),
        12.0,
        ui,
    )
}

/// A bordered section card with a title, a one-line description, and content.
fn inspector_card(title: &'static str, description: &'static str, content: El, ui: &Ui) -> El {
    let p = ui.p;
    col()
        .w_full()
        .gap(16.0)
        .padding(20.0)
        .radius(11.0)
        .border(1.0, p.line)
        .fill(p.card)
        .child(
            col()
                .w_full()
                .gap(4.0)
                .child(font_text(title, 13.0, SEMIBOLD, p.text, ui))
                .child(font_text(description, 12.0, 400.0, p.muted, ui).wrap()),
        )
        .child(content)
}
