use rune::{El, TextEdit, Tx, col, row};
use rune_kit::{Button, ButtonVariant, Checkbox, TextInput};

use super::{
    Editor, Workspace, edit,
    environment::Section,
    view::{caption, font_text},
};
use crate::theme::{SEMIBOLD, Ui};

fn tools_count(s: &mut Workspace) -> &mut TextEdit {
    match &mut s.editor {
        Some(Editor::Tools { count, .. }) => count,
        _ => &mut s.scratch,
    }
}

fn tools_domain(s: &mut Workspace) -> &mut TextEdit {
    match &mut s.editor {
        Some(Editor::Tools { domain, .. }) => domain,
        _ => &mut s.scratch,
    }
}

fn idp_base_url(s: &mut Workspace) -> &mut TextEdit {
    match &mut s.editor {
        Some(Editor::Idp { base_url, .. }) => base_url,
        _ => &mut s.scratch,
    }
}

impl Workspace {
    pub(super) fn open_tools(&mut self) {
        if self.busy || self.selected.is_none() {
            return;
        }
        let mut count = edit("10");
        count.focused = true;
        self.open_editor(Editor::Tools {
            count,
            domain: edit("greendale.edu"),
        });
        self.failed = false;
    }

    pub(super) fn open_idp(&mut self) {
        if self.busy {
            return;
        }
        let config = match self.store.global_config() {
            Ok(config) => config,
            Err(error) => {
                self.fail(error.to_string());
                return;
            }
        };
        let mut base_url = edit(&config.idp_base_url);
        base_url.focused = true;
        self.open_editor(Editor::Idp {
            base_url,
            trust_proxy: config.trust_forwarded_headers,
        });
        self.failed = false;
    }

    /// Switches the environment wizard to the step at `index`.
    pub(super) fn set_environment_step(&mut self, index: usize) {
        if index >= Section::STEPS.len() {
            return;
        }
        // Moving forward requires every step being left to be valid.
        let blocked = match &self.editor {
            Some(Editor::Environment { name, settings, .. })
                if index > settings.section.index() =>
            {
                Section::STEPS[settings.section.index()..index]
                    .iter()
                    .find_map(|(section, _)| {
                        settings
                            .section_error(name, *section)
                            .map(|message| (*section, message))
                    })
            }
            _ => None,
        };
        if let Some((section, message)) = blocked {
            self.show_environment_error(section, message);
            return;
        }
        if let Some(Editor::Environment { settings, .. }) = &mut self.editor {
            settings.section = Section::STEPS[index].0;
        }
        self.message.clear();
        self.failed = false;
    }

    pub(super) fn tools_body(&self, count: &TextEdit, domain: &TextEdit, ui: &Ui) -> El {
        let k = &ui.k;
        let disabled = self.busy || self.selected.is_none();
        let button = |key: &'static str,
                      label: &'static str,
                      variant: ButtonVariant,
                      press: fn(&mut Workspace, &mut Tx)| {
            Button::new(label)
                .variant(variant)
                .disabled(disabled)
                .on_press_tx(press)
                .build(k)
                .key(key)
        };
        col()
            .key("tools")
            .w_full()
            .gap(16.0)
            .child(tool_card(
                "tool-seed",
                "Greendale sample",
                "Load a small realistic directory: 10 named users (one inactive) and 3 overlapping groups. Loading twice adds nothing.",
                row().w_full().justify_end().child(button(
                    "seed",
                    "Load Greendale sample",
                    ButtonVariant::Contrast,
                    |s, _| s.seed_sample(),
                )),
                ui,
            ))
            .child(tool_card(
                "tool-create",
                "Create users",
                "Generate active test users. They will be ready for the next SCIM sync.",
                col()
                    .w_full()
                    .gap(12.0)
                    .child(
                        row()
                            .w_full()
                            .gap(12.0)
                            .items_start()
                            .child(labeled_input(
                                "tool-count",
                                "Number",
                                "Number of users",
                                count,
                                tools_count,
                                ui,
                            ))
                            .child(labeled_input(
                                "tool-domain",
                                "Email domain",
                                "Email domain",
                                domain,
                                tools_domain,
                                ui,
                            )),
                    )
                    .child(row().w_full().justify_end().child(button(
                        "create-users",
                        "Create users",
                        ButtonVariant::Contrast,
                        |s, _| s.create_users(),
                    ))),
                ui,
            ))
            .child(tool_card(
                "tool-bulk",
                "Bulk user actions",
                "Apply the same state change to every non-deleted user.",
                row()
                    .w_full()
                    .flex_wrap()
                    .gap(8.0)
                    .child(button(
                        "activate-all",
                        "Activate all",
                        ButtonVariant::Outline,
                        |s, _| s.set_all_active(true),
                    ))
                    .child(button(
                        "deactivate-all",
                        "Deactivate all",
                        ButtonVariant::Outline,
                        |s, _| s.set_all_active(false),
                    ))
                    .child(button(
                        "delete-all",
                        "Delete all users",
                        ButtonVariant::Danger,
                        |s, _| {
                            s.open_editor(Editor::ConfirmTool {
                                action: "delete-all",
                            })
                        },
                    ))
                    .child(button(
                        "clear-local",
                        "Clear local directory",
                        ButtonVariant::Danger,
                        |s, _| {
                            s.open_editor(Editor::ConfirmTool {
                                action: "clear-local",
                            })
                        },
                    )),
                ui,
            ))
            .child(tool_card(
                "tool-backup",
                "Backup and restore",
                "Backups contain client secrets, SCIM bearer tokens, signing keys, users, and operation history. Store them securely.",
                row()
                    .w_full()
                    .flex_wrap()
                    .gap(8.0)
                    .child(button(
                        "backup",
                        "Download backup",
                        ButtonVariant::Outline,
                        |s, tx| s.export_backup(tx),
                    ))
                    .child(button(
                        "restore",
                        "Restore backup…",
                        ButtonVariant::Danger,
                        |s, tx| s.import_backup(tx),
                    )),
                ui,
            ))
    }

    fn seed_sample(&mut self) {
        let Some(environment) = self.selected.clone() else {
            return;
        };
        self.command(move |store| {
            let result = store.seed_sample(&environment)?;
            Ok((
                format!(
                    "Added {} users and {} groups",
                    result.users_added, result.groups_added
                ),
                None,
            ))
        });
    }

    fn create_users(&mut self) {
        let Some(environment) = self.selected.clone() else {
            return;
        };
        let Some(Editor::Tools { count, domain }) = &self.editor else {
            return;
        };
        let count = count.text.clone();
        let domain = domain.text.clone();
        self.command(move |store| {
            let count = count.trim().parse().map_err(|_| {
                scimtest_core::Error::Validation(
                    "Number of users must be between 1 and 10000".into(),
                )
            })?;
            let result = store.create_users(&environment, count, &domain)?;
            Ok((format!("Created {} users", result.users_changed), None))
        });
    }

    fn set_all_active(&mut self, active: bool) {
        let Some(environment) = self.selected.clone() else {
            return;
        };
        self.command(move |store| {
            let result = store.set_all_active(&environment, active)?;
            Ok((format!("Changed {} users", result.users_changed), None))
        });
    }

    pub(super) fn idp_body(&self, base_url: &TextEdit, trust_proxy: bool, ui: &Ui) -> El {
        let p = ui.p;
        let snapshot = &self.tunnel_snapshot;
        let mut status = col().key("tunnel-status").w_full().gap(4.0);
        if snapshot.connected {
            status = status.child(
                row()
                    .gap(4.0)
                    .child(font_text("Tunnel connected:", 12.0, 400.0, p.success, ui))
                    .child(font_text(
                        snapshot.public_url.clone().unwrap_or_default(),
                        12.0,
                        400.0,
                        p.muted,
                        ui,
                    )),
            );
            if let Some(ip) = &snapshot.client_ip {
                status = status.child(font_text(
                    format!("Sign-in chooser is limited to your public IP {ip}."),
                    12.0,
                    400.0,
                    p.muted,
                    ui,
                ));
            }
            status = status.child(font_text(
                "Only OIDC and SAML endpoints are exposed through the tunnel.",
                12.0,
                400.0,
                p.muted,
                ui,
            ));
        } else {
            status = status.child(font_text("Tunnel not connected.", 12.0, 400.0, p.muted, ui));
        }
        col()
            .key("idp")
            .w_full()
            .gap(16.0)
            .child(
                font_text("Global IDP and tunnel settings", 13.0, SEMIBOLD, p.text, ui)
                    .role("heading"),
            )
            .child(status)
            .child(
                col()
                    .key("idp-base-url")
                    .w_full()
                    .gap(8.0)
                    .child(font_text("IDP base URL", 12.0, 400.0, p.text, ui).a11y_hidden())
                    .child(
                        TextInput::new(base_url)
                            .width(None)
                            .label("IDP base URL")
                            .placeholder("https://idp.example.com")
                            .on_edit(idp_base_url)
                            .on_change(|s: &mut Workspace, _: &mut Tx| s.editor_dirty = true)
                            .build(&ui.k)
                            .key("input"),
                    )
                    .child(
                        caption(
                            "Set this only when OIDC/SAML clients need a public issuer URL different from the current request host.",
                            ui,
                        )
                        .w_full()
                        .wrap(),
                    ),
            )
            .child(
                col()
                    .w_full()
                    .gap(8.0)
                    .child(font_text("Reverse proxy", 12.0, 400.0, p.text, ui))
                    .child(
                        row()
                            .w_full()
                            .padding(12.0)
                            .radius(6.0)
                            .border(1.0, p.line)
                            .child(
                                Checkbox::new(trust_proxy)
                                    .label("Trust X-Forwarded-Proto from a local reverse proxy")
                                    .disabled(self.busy)
                                    .on_toggle(|s: &mut Workspace| {
                                        if let Some(Editor::Idp { trust_proxy, .. }) =
                                            &mut s.editor
                                        {
                                            *trust_proxy = !*trust_proxy;
                                            s.editor_dirty = true;
                                        }
                                    })
                                    .build(&ui.k)
                                    .key("trust-forwarded-headers"),
                            ),
                    ),
            )
    }
}

fn tool_card(
    key: &'static str,
    title: &'static str,
    description: &'static str,
    controls: El,
    ui: &Ui,
) -> El {
    col()
        .key(key)
        .role("group")
        .label(title)
        .w_full()
        .gap(12.0)
        .padding(16.0)
        .radius(6.0)
        .border(1.0, ui.p.line)
        .child(font_text(title, 13.0, SEMIBOLD, ui.p.text, ui))
        .child(caption(description, ui).w_full().wrap())
        .child(controls)
}

fn labeled_input(
    key: &'static str,
    label: &'static str,
    placeholder: &'static str,
    edit: &TextEdit,
    access: fn(&mut Workspace) -> &mut TextEdit,
    ui: &Ui,
) -> El {
    col()
        .key(key)
        .grow(1.0)
        .min_w(0.0)
        .gap(8.0)
        .child(font_text(label, 12.0, 400.0, ui.p.text, ui).a11y_hidden())
        .child(
            TextInput::new(edit)
                .width(None)
                .label(label)
                .placeholder(placeholder)
                .on_edit(access)
                .on_change(|s: &mut Workspace, _: &mut Tx| s.editor_dirty = true)
                .build(&ui.k)
                .key("input"),
        )
}
