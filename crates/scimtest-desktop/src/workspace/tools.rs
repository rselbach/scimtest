use gpui::{Context, Div, Entity, IntoElement, Window, div, prelude::*, px};
use gpui_component::{
    Disableable, StyledExt,
    button::{Button, ButtonVariants},
    checkbox::Checkbox,
    input::{Input, InputState},
};

use super::{Editor, Workspace, input};
use crate::theme::Palette;

impl Workspace {
    pub(super) fn open_tools(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.busy || self.selected.is_none() {
            return;
        }
        self.message.clear();
        self.failed = false;
        self.editor = Some(Editor::Tools {
            count: input("10", "Number of users", window, cx),
            domain: input("greendale.edu", "Email domain", window, cx),
        });
        cx.notify();
    }

    pub(super) fn open_idp(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        let config = match self.store.global_config() {
            Ok(config) => config,
            Err(error) => {
                self.message = error.to_string();
                self.failed = true;
                cx.notify();
                return;
            }
        };
        self.message.clear();
        self.failed = false;
        self.editor = Some(Editor::Idp {
            base_url: input(&config.idp_base_url, "https://idp.example.com", window, cx),
            trust_proxy: config.trust_forwarded_headers,
        });
        cx.notify();
    }

    /// Switches the environment wizard to the step at `index`.
    pub(super) fn set_environment_step(&mut self, index: usize, cx: &mut Context<Self>) {
        if index >= super::environment::Section::STEPS.len() {
            return;
        }
        // Moving forward requires every step being left to be valid.
        let blocked = match &self.editor {
            Some(Editor::Environment { name, settings, .. })
                if index > settings.section.index() =>
            {
                super::environment::Section::STEPS[settings.section.index()..index]
                    .iter()
                    .find_map(|(section, _)| {
                        settings
                            .section_error(name, *section, cx)
                            .map(|message| (*section, message))
                    })
            }
            _ => None,
        };
        if let Some((section, message)) = blocked {
            self.show_environment_error(section, message, cx);
            return;
        }
        if let Some(Editor::Environment { settings, .. }) = &mut self.editor {
            settings.section = super::environment::Section::STEPS[index].0;
        }
        self.message.clear();
        self.failed = false;
        cx.notify();
    }

    pub(super) fn tools_body(
        &self,
        count: &Entity<InputState>,
        domain: &Entity<InputState>,
        cx: &mut Context<Self>,
    ) -> Div {
        let palette = Palette::get(cx);
        let busy = self.busy;
        let has_environment = self.selected.is_some();
        let create_count = count.clone();
        let create_domain = domain.clone();
        div()
            .v_flex()
            .gap_4()
            .child(tool_card(
                "Greendale sample",
                "Load a small realistic directory: 10 named users (one inactive) and 3 overlapping groups. Loading twice adds nothing.",
                palette,
                div().h_flex().justify_end().child(
                    Button::new("seed")
                        .label("Load Greendale sample")
                        .h(px(29.))
                        .primary()
                        .disabled(busy || !has_environment)
                        .on_click(cx.listener(|view, _, _, cx| {
                            let Some(environment) = view.selected.clone() else {
                                return;
                            };
                            view.command(
                                move |store| {
                                    let result = store.seed_sample(&environment)?;
                                    Ok((
                                        format!(
                                            "Added {} users and {} groups",
                                            result.users_added, result.groups_added
                                        ),
                                        None,
                                    ))
                                },
                                cx,
                            );
                        })),
                ),
            ))
            .child(tool_card(
                "Create users",
                "Generate active test users. They will be ready for the next SCIM sync.",
                palette,
                div()
                    .v_flex()
                    .gap_3()
                    .child(
                        div()
                            .h_flex()
                            .gap_3()
                            .items_start()
                            .child(labeled_input("Number", count))
                            .child(labeled_input("Email domain", domain)),
                    )
                    .child(
                        div().h_flex().justify_end().child(
                            Button::new("create-users")
                                .label("Create users")
                                .h(px(29.))
                                .primary()
                                .disabled(busy || !has_environment)
                                .on_click(cx.listener(move |view, _, _, cx| {
                                    let Some(environment) = view.selected.clone() else {
                                        return;
                                    };
                                    let count = create_count.read(cx).value().to_string();
                                    let domain = create_domain.read(cx).value().to_string();
                                    view.command(
                                        move |store| {
                                            let count = count.trim().parse().map_err(|_| {
                                                scimtest_core::Error::Validation(
                                                    "Number of users must be between 1 and 10000"
                                                        .into(),
                                                )
                                            })?;
                                            let result =
                                                store.create_users(&environment, count, &domain)?;
                                            Ok((
                                                format!("Created {} users", result.users_changed),
                                                None,
                                            ))
                                        },
                                        cx,
                                    );
                                })),
                        ),
                    ),
            ))
            .child(tool_card(
                "Bulk user actions",
                "Apply the same state change to every non-deleted user.",
                palette,
                div()
                    .h_flex()
                    .flex_wrap()
                    .gap_2()
                    .child(
                        Button::new("activate-all")
                            .label("Activate all")
                            .h(px(29.))
                            .outline()
                            .disabled(busy || !has_environment)
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.set_all_active(true, cx);
                            })),
                    )
                    .child(
                        Button::new("deactivate-all")
                            .label("Deactivate all")
                            .h(px(29.))
                            .outline()
                            .disabled(busy || !has_environment)
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.set_all_active(false, cx);
                            })),
                    )
                    .child(
                        Button::new("delete-all")
                            .label("Delete all users")
                            .h(px(29.))
                            .outline()
                            .danger()
                            .disabled(busy || !has_environment)
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.editor = Some(Editor::ConfirmTool {
                                    action: "delete-all",
                                });
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("clear-local")
                            .label("Clear local directory")
                            .h(px(29.))
                            .outline()
                            .danger()
                            .disabled(busy || !has_environment)
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.editor = Some(Editor::ConfirmTool {
                                    action: "clear-local",
                                });
                                cx.notify();
                            })),
                    ),
            ))
            .child(tool_card(
                "Backup and restore",
                "Backups contain client secrets, SCIM bearer tokens, signing keys, users, and operation history. Store them securely.",
                palette,
                div()
                    .h_flex()
                    .flex_wrap()
                    .gap_2()
                    .child(
                        Button::new("backup")
                            .label("Download backup")
                            .h(px(29.))
                            .outline()
                            .disabled(busy || !has_environment)
                            .on_click(cx.listener(|view, _, _, cx| view.export_backup(cx))),
                    )
                    .child(
                        Button::new("restore")
                            .label("Restore backup…")
                            .h(px(29.))
                            .outline()
                            .danger()
                            .disabled(busy || !has_environment)
                            .on_click(cx.listener(|view, _, _, cx| view.import_backup(cx))),
                    ),
            ))
    }

    fn set_all_active(&mut self, active: bool, cx: &mut Context<Self>) {
        let Some(environment) = self.selected.clone() else {
            return;
        };
        self.command(
            move |store| {
                let result = store.set_all_active(&environment, active)?;
                Ok((format!("Changed {} users", result.users_changed), None))
            },
            cx,
        );
    }

    pub(super) fn idp_body(
        &self,
        base_url: &Entity<InputState>,
        trust_proxy: bool,
        cx: &mut Context<Self>,
    ) -> Div {
        let palette = Palette::get(cx);
        let snapshot = &self.tunnel_snapshot;
        let mut status = div().v_flex().gap_1().text_size(px(12.));
        if snapshot.connected {
            status = status.child(
                div()
                    .h_flex()
                    .gap_1()
                    .child(div().text_color(palette.success).child("Tunnel connected:"))
                    .child(
                        div()
                            .text_color(palette.muted)
                            .child(snapshot.public_url.clone().unwrap_or_default()),
                    ),
            );
            if let Some(ip) = &snapshot.client_ip {
                status = status.child(div().text_color(palette.muted).child(format!(
                    "Sign-in chooser is limited to your public IP {ip}."
                )));
            }
            status = status.child(
                div()
                    .text_color(palette.muted)
                    .child("Only OIDC and SAML endpoints are exposed through the tunnel."),
            );
        } else {
            status = status.child(
                div()
                    .text_color(palette.muted)
                    .child("Tunnel not connected."),
            );
        }
        div()
            .v_flex()
            .gap_4()
            .child(
                div()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("Global IDP and tunnel settings"),
            )
            .child(status)
            .child(
                div()
                    .v_flex()
                    .gap_2()
                    .child(div().text_size(px(12.)).child("IDP base URL"))
                    .child(Input::new(base_url).aria_label("IDP base URL"))
                    .child(
                        div()
                            .text_size(px(11.))
                            .text_color(palette.muted)
                            .child("Set this only when OIDC/SAML clients need a public issuer URL different from the current request host."),
                    ),
            )
            .child(
                div()
                    .v_flex()
                    .gap_2()
                    .child(div().text_size(px(12.)).child("Reverse proxy"))
                    .child(
                        div()
                            .p_3()
                            .rounded_md()
                            .border_1()
                            .border_color(palette.line)
                            .child(
                                Checkbox::new("trust-forwarded-headers")
                                    .label("Trust X-Forwarded-Proto from a local reverse proxy")
                                    .checked(trust_proxy)
                                    .disabled(self.busy)
                                    .on_click(cx.listener(|view, checked: &bool, _, cx| {
                                        if let Some(Editor::Idp { trust_proxy, .. }) =
                                            &mut view.editor
                                        {
                                            *trust_proxy = *checked;
                                        }
                                        cx.notify();
                                    })),
                            ),
                    ),
            )
    }
}

fn tool_card(
    title: &'static str,
    description: &'static str,
    palette: Palette,
    controls: impl IntoElement,
) -> Div {
    div()
        .v_flex()
        .gap_3()
        .p_4()
        .rounded_md()
        .border_1()
        .border_color(palette.line)
        .child(div().font_weight(gpui::FontWeight::SEMIBOLD).child(title))
        .child(
            div()
                .text_size(px(12.))
                .text_color(palette.muted)
                .child(description),
        )
        .child(controls)
}

fn labeled_input(label: &'static str, state: &Entity<InputState>) -> Div {
    div()
        .v_flex()
        .flex_1()
        .min_w_0()
        .gap_2()
        .child(div().text_size(px(12.)).child(label))
        .child(Input::new(state).aria_label(label))
}
