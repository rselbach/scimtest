use std::collections::BTreeSet;

use rune::{El, ScrollSpec, TextEdit, Tx, col, el, icon, row};
use rune_kit::{Button, ButtonVariant, Checkbox, Dialog, TextArea, TextInput};
use scimtest_core::model::OperationLog;

use super::{
    DeleteTarget, Editor, Workspace,
    view::{Choice, caption, dropdown, font_text, rule, status_text},
};
use crate::{
    icons,
    theme::{MEDIUM, SEMIBOLD, Ui},
};

/// A labelled text field whose edits mark the open editor as changed.
pub(crate) fn field(
    key: impl Into<String>,
    label: &'static str,
    hint: &'static str,
    placeholder: &'static str,
    edit: &TextEdit,
    access: impl Fn(&mut Workspace) -> &mut TextEdit + 'static,
    ui: &Ui,
) -> El {
    let mut heading = row()
        .w_full()
        .justify_between()
        .child(font_text(label, 12.0, 400.0, ui.p.text, ui).a11y_hidden());
    if !hint.is_empty() {
        heading = heading.child(caption(hint, ui).a11y_hidden());
    }
    col()
        .key(key.into())
        .grow(1.0)
        .min_w(0.0)
        .gap(8.0)
        .child(heading)
        .child(
            TextInput::new(edit)
                .label(label)
                .placeholder(placeholder)
                .width(None)
                .on_edit(access)
                .on_change(|s: &mut Workspace, _: &mut Tx| s.editor_dirty = true)
                .build(&ui.k)
                .key("input"),
        )
}

pub(crate) fn two_columns(left: El, right: El) -> El {
    row()
        .w_full()
        .items_start()
        .gap(16.0)
        .child(left)
        .child(right)
}

fn user_field(s: &mut Workspace, index: usize) -> &mut TextEdit {
    match &mut s.editor {
        Some(Editor::User { fields, .. }) => &mut fields[index],
        _ => &mut s.scratch,
    }
}

fn user_attributes(s: &mut Workspace) -> &mut TextEdit {
    match &mut s.editor {
        Some(Editor::User { attributes, .. }) => attributes,
        _ => &mut s.scratch,
    }
}

fn group_name(s: &mut Workspace) -> &mut TextEdit {
    match &mut s.editor {
        Some(Editor::Group { name, .. }) => name,
        _ => &mut s.scratch,
    }
}

fn group_search(s: &mut Workspace) -> &mut TextEdit {
    match &mut s.editor {
        Some(Editor::Group { search, .. }) => search,
        _ => &mut s.scratch,
    }
}

/// A paragraph of the dialog's body.
fn paragraph(key: &'static str, value: impl Into<String>, muted: bool, ui: &Ui) -> El {
    font_text(
        value,
        13.0,
        400.0,
        if muted { ui.p.muted } else { ui.p.text },
        ui,
    )
    .key(key)
    .w_full()
    .wrap()
}

impl Workspace {
    pub(super) fn editor(&self, ui: &Ui, layer: &mut Vec<El>) {
        let p = ui.p;
        let Some(editor) = &self.editor else {
            return;
        };
        if self.account_locked() || self.account_open {
            return;
        }
        let title = match editor {
            Editor::Lifecycle(_) => "Run a lifecycle scenario".into(),
            Editor::Faults(_) => "Custom faults".into(),
            Editor::Environment { id: Some(_), .. } => "Set up environment".into(),
            Editor::Environment { .. } => "Add environment".into(),
            Editor::User { id: Some(_), .. } => "Edit User".into(),
            Editor::User { .. } => "Add User".into(),
            Editor::Group { id: Some(_), .. } => "Edit Group".into(),
            Editor::Group { .. } => "Add Group".into(),
            Editor::Delete { .. } => "Confirm deletion".into(),
            Editor::BulkDelete { .. } => "Delete selected entries".into(),
            Editor::History { noun: "", name, .. } => name.clone(),
            Editor::History { noun, name, .. } => format!("{noun} History: {name}"),
            Editor::RestoreBackup { .. } => "Restore environment backup".into(),
            Editor::Tools { .. } => "Bulk tools".into(),
            Editor::Idp { .. } => "IDP and tunnel settings".into(),
            Editor::ConfirmTool {
                action: "clear-local",
            } => "Clear local directory".into(),
            Editor::ConfirmTool { .. } => "Delete all users".to_owned(),
        };
        let subtitle = match editor {
            Editor::Environment { .. } => {
                "The authentication and provisioning context used while testing".into()
            }
            Editor::History { .. } => "Newest first".into(),
            Editor::Tools { .. } => "Create or update many test users at once.".into(),
            Editor::Idp { .. } => String::new(),
            _ => self
                .directory()
                .map(|directory| directory.environment.name.clone())
                .unwrap_or_default(),
        };
        let width = match editor {
            Editor::Environment { .. } | Editor::Group { .. } => 880.0,
            Editor::History { .. } => 960.0,
            _ => 640.0,
        };
        let mut body = col().key("editor-body").w_full().gap(20.0).padding(20.0);
        body = match editor {
            Editor::Lifecycle(form) => body.child(form.fields(self, ui, layer)),
            Editor::Faults(form) => body.child(form.fields(self, ui, layer)),
            Editor::Environment {
                id,
                name,
                slug,
                settings,
            } => body.child(settings.body(self, name, slug, id.as_deref(), ui, layer)),
            Editor::User {
                id,
                fields,
                active,
                manager,
                attributes,
                ..
            } => body.child(self.user_form(
                id.as_deref(),
                fields,
                *active,
                manager,
                attributes,
                ui,
                layer,
            )),
            Editor::Group {
                name,
                search,
                members,
                ..
            } => body.child(self.group_form(name, search, members, ui)),
            Editor::Delete { target, name, .. } => body
                .child(
                    font_text(format!("Delete {name}?"), 13.0, MEDIUM, p.text, ui)
                        .key("delete-question")
                        .wrap(),
                )
                .child(paragraph(
                    "delete-detail",
                    match target {
                        DeleteTarget::Environment => {
                            "This removes the environment and its entire directory."
                        }
                        DeleteTarget::User => {
                            "This removes the user from this directory and its groups."
                        }
                        DeleteTarget::Group => {
                            "This removes the group. Its users stay in the directory."
                        }
                    },
                    true,
                    ui,
                )),
            Editor::Tools { count, domain } => body.child(self.tools_body(count, domain, ui)),
            Editor::Idp {
                base_url,
                trust_proxy,
            } => body.child(self.idp_body(base_url, *trust_proxy, ui)),
            Editor::ConfirmTool { action } => body.child(paragraph(
                "tool-question",
                if *action == "clear-local" {
                    "Remove all local users, groups, sync state, and operation history? Remote resources stay in place."
                } else {
                    "Delete every user in this environment? Users tracked by SCIM remain available to restore until their remote deletion completes."
                },
                false,
                ui,
            )),
            Editor::RestoreBackup { backup } => body
                .child(paragraph(
                    "restore-question",
                    format!(
                        "Restore the backup from {}? It contains {} user{} and {} group{}.",
                        backup.exported_at,
                        backup.state.users.len(),
                        if backup.state.users.len() == 1 { "" } else { "s" },
                        backup.state.groups.len(),
                        if backup.state.groups.len() == 1 { "" } else { "s" },
                    ),
                    false,
                    ui,
                ))
                .child(paragraph(
                    "restore-detail",
                    "This replaces the selected environment. A safety copy of the current state will be saved first.",
                    true,
                    ui,
                )),
            Editor::BulkDelete { ids, .. } => body
                .child(paragraph(
                    "delete-question",
                    format!(
                        "Delete {} selected {}?",
                        ids.len(),
                        if ids.len() == 1 { "entry" } else { "entries" }
                    ),
                    false,
                    ui,
                ))
                .child(paragraph(
                    "delete-detail",
                    if self
                        .directory()
                        .is_some_and(|directory| directory.tracks_scim())
                    {
                        "Entries remain available to restore until their remote deletion completes."
                    } else {
                        "This removes the selected entries from this directory."
                    },
                    true,
                    ui,
                )),
            Editor::History {
                entries, expanded, ..
            } => body.child(self.history_entries(entries, expanded, ui)),
        };
        if self.failed
            && !self.message.is_empty()
            && !matches!(editor, Editor::Faults(_) | Editor::Lifecycle(_))
        {
            body = body.child(status_text("editor-error", &self.message, true, ui));
        }
        let mut dialog = Dialog::new("editor", title)
            .open(true)
            .width(width)
            .fit()
            .on_close(|s: &mut Workspace| s.request_editor_dismiss())
            .child(rule(p))
            .child(
                col()
                    .key("editor-content")
                    .w_full()
                    .max_h(560.0)
                    .scroll(ScrollSpec {
                        stick_bottom: false,
                    })
                    .child(body),
            );
        if !subtitle.is_empty() {
            dialog = dialog.description(subtitle);
        }
        if let Some(footer) = self.editor_footer(editor, ui) {
            dialog = dialog.child(rule(p)).child(footer);
        }
        dialog.build(&ui.k, layer);
    }

    /// Footer actions for the open editor. Returns `None` for read-only panels.
    fn editor_footer(&self, editor: &Editor, ui: &Ui) -> Option<El> {
        let k = &ui.k;
        if matches!(editor, Editor::History { .. } | Editor::Tools { .. }) {
            return None;
        }
        let confirming = matches!(
            editor,
            Editor::Delete { .. } | Editor::BulkDelete { .. } | Editor::ConfirmTool { .. }
        );
        let save_label = match editor {
            Editor::Lifecycle(_) => "Run scenario",
            Editor::Faults(_) => "Arm faults",
            Editor::User { .. } => "Save user",
            Editor::Group { .. } => "Save group",
            Editor::Environment { .. } => "Save environment",
            Editor::Idp { .. } => "Save config",
            Editor::Delete { .. } | Editor::BulkDelete { .. } => "Delete",
            Editor::History { .. } | Editor::Tools { .. } => "Close",
            Editor::RestoreBackup { .. } => "Restore backup",
            Editor::ConfirmTool { .. } => "Continue",
        };
        let save = Button::new(if self.busy { "Saving…" } else { save_label })
            .variant(if confirming {
                ButtonVariant::Danger
            } else {
                ButtonVariant::Contrast
            })
            .disabled(self.busy)
            .on_press(|s: &mut Workspace| s.save())
            .build(k)
            .key("save")
            .default_button();
        let cancel = Button::new("Cancel")
            .variant(ButtonVariant::Ghost)
            .disabled(self.busy)
            .on_press(|s: &mut Workspace| s.close_editor())
            .build(k)
            .key("cancel");
        let mut footer = row()
            .key("editor-footer")
            .w_full()
            .gap(8.0)
            .px(20.0)
            .py(16.0)
            .center_y();
        footer = match editor {
            Editor::Environment { settings, .. } => footer
                .child(cancel)
                .child(el().grow(1.0))
                .child(settings.nav(self, ui))
                .child(save),
            Editor::Idp { .. } => footer
                .child(
                    Button::new("Copy local API URL")
                        .variant(ButtonVariant::Ghost)
                        .on_press_tx(|s: &mut Workspace, tx: &mut Tx| {
                            tx.copy(s.api_url.clone());
                            s.message = "Local API URL copied".into();
                            s.failed = false;
                        })
                        .build(k)
                        .key("copy-api"),
                )
                .child(el().grow(1.0))
                .child(cancel)
                .child(save),
            Editor::User { id: Some(id), .. } if self.scim_enabled() => {
                let id = id.clone();
                footer
                    .child(
                        Button::new("Push to SCIM")
                            .variant(ButtonVariant::Ghost)
                            .disabled(self.busy)
                            .on_press(move |s: &mut Workspace| {
                                s.close_editor();
                                s.scim_action("push", Some(("user".into(), id.clone())));
                            })
                            .build(k)
                            .key("push-user"),
                    )
                    .child(el().grow(1.0))
                    .child(cancel)
                    .child(save)
            }
            _ => footer.child(el().grow(1.0)).child(cancel).child(save),
        };
        if matches!(editor, Editor::Faults(_) | Editor::Lifecycle(_)) && self.failed {
            footer = footer.child(status_text("editor-error", &self.message, true, ui));
        }
        Some(footer)
    }

    fn scim_enabled(&self) -> bool {
        self.directory()
            .is_some_and(|directory| directory.environment.settings.scim_enabled)
    }

    /// A disclosure header that expands or collapses the section it names.
    pub(crate) fn disclosure(&self, key: &'static str, label: &'static str, ui: &Ui) -> El {
        let p = ui.p;
        let open = self.disclosures.contains(key);
        row()
            .key(key)
            .role("button")
            .label(label)
            .expanded(open)
            .focusable(true)
            .gap(6.0)
            .center_y()
            .cursor(rune::Cursor::Pointer)
            .child(
                icon(
                    if open {
                        &icons::CHEVRON_DOWN
                    } else {
                        &icons::CHEVRON_RIGHT
                    },
                    12.0,
                )
                .color(p.accent),
            )
            .child(font_text(label, 12.0, SEMIBOLD, p.accent, ui).a11y_hidden())
            .on_press(move |s: &mut Workspace| {
                if !s.disclosures.remove(key) {
                    s.disclosures.insert(key);
                }
            })
    }

    #[allow(clippy::too_many_arguments)]
    fn user_form(
        &self,
        id: Option<&str>,
        fields: &[TextEdit; 9],
        active: bool,
        manager: &str,
        attributes: &TextEdit,
        ui: &Ui,
        layer: &mut Vec<El>,
    ) -> El {
        let input = |index: usize, label: &'static str, hint: &'static str, placeholder| {
            field(
                format!("field-{index}"),
                label,
                hint,
                placeholder,
                &fields[index],
                move |s: &mut Workspace| user_field(s, index),
                ui,
            )
        };
        let mut form = col()
            .key("user-form")
            .w_full()
            .gap(12.0)
            .child(two_columns(
                input(
                    3,
                    "Username",
                    "Uses email when left blank",
                    "Defaults to email",
                ),
                input(2, "Email", "", "troy@greendale.edu"),
            ))
            .child(two_columns(
                input(0, "Given name", "", "Troy"),
                input(1, "Family name", "Optional", "Barnes"),
            ))
            .child(
                Checkbox::new(active)
                    .label("Active")
                    .disabled(self.busy)
                    .on_toggle(|s: &mut Workspace| {
                        if let Some(Editor::User { active, .. }) = &mut s.editor {
                            *active = !*active;
                            s.editor_dirty = true;
                        }
                    })
                    .build(&ui.k)
                    .key("user-active"),
            )
            .child(self.disclosure("user-enterprise", "Enterprise attributes", ui));
        if self.disclosures.contains("user-enterprise") {
            let manager_name = self
                .directory()
                .and_then(|directory| directory.users.iter().find(|user| user.id == manager))
                .map(|user| format!("{} {}", user.fields.given_name, user.fields.family_name))
                .unwrap_or_else(|| {
                    if manager.is_empty() {
                        "No manager".into()
                    } else {
                        "Previous manager (unavailable)".into()
                    }
                });
            let candidates = self
                .directory()
                .map(|directory| {
                    directory
                        .users
                        .iter()
                        .filter(|user| !user.deleted && Some(user.id.as_str()) != id)
                        .map(|user| {
                            (
                                user.id.clone(),
                                format!("{} {}", user.fields.given_name, user.fields.family_name),
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let choices = std::iter::once((String::new(), "No manager".to_owned()))
                .chain(candidates)
                .map(|(candidate, name)| {
                    let checked = candidate == manager;
                    Choice::new(name, move |s: &mut Workspace| {
                        if let Some(Editor::User { manager, .. }) = &mut s.editor {
                            *manager = candidate.clone();
                            s.editor_dirty = true;
                        }
                    })
                    .checked(checked)
                })
                .collect();
            form = form.child(
                col()
                    .key("user-enterprise-fields")
                    .w_full()
                    .gap(16.0)
                    .pl(12.0)
                    .child(two_columns(
                        input(4, "Employee number", "", "GCC42"),
                        input(5, "Cost center", "", "Air conditioning"),
                    ))
                    .child(two_columns(
                        input(6, "Organization", "", "Greendale Community College"),
                        input(7, "Division", "", "Annex"),
                    ))
                    .child(two_columns(
                        input(8, "Department", "", "Film Studies"),
                        col()
                            .key("manager")
                            .grow(1.0)
                            .min_w(0.0)
                            .gap(8.0)
                            .child(font_text("Manager", 12.0, 400.0, ui.p.text, ui).a11y_hidden())
                            .child(
                                dropdown(
                                    self,
                                    "manager-picker",
                                    manager_name.clone(),
                                    None,
                                    self.busy,
                                    choices,
                                    ui,
                                    layer,
                                )
                                .label(format!("Manager: {manager_name}")),
                            ),
                    )),
            );
        }
        form = form.child(self.disclosure("user-custom", "Custom attributes", ui));
        if self.disclosures.contains("user-custom") {
            form = form.child(
                col()
                    .key("user-custom-fields")
                    .w_full()
                    .gap(8.0)
                    .pl(12.0)
                    .child(caption("One name=value per line.", ui))
                    .child(
                        TextArea::new(attributes)
                            .width(None)
                            .label("Custom attributes (one name=value per line)")
                            .placeholder("role=student")
                            .auto_grow(3, 6)
                            .on_edit(user_attributes)
                            .on_change(|s: &mut Workspace, _: &mut Tx| s.editor_dirty = true)
                            .build(&ui.k)
                            .key("attributes"),
                    ),
            );
        }
        form
    }

    fn group_form(&self, name: &TextEdit, search: &TextEdit, members: &[String], ui: &Ui) -> El {
        let p = ui.p;
        let query = search.text.to_lowercase();
        let users = self
            .directory()
            .map(|directory| {
                directory
                    .users
                    .iter()
                    .filter(|user| !user.deleted)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let total = users.len();
        let matching = users
            .iter()
            .filter(|user| {
                format!(
                    "{} {} {} {}",
                    user.fields.given_name,
                    user.fields.family_name,
                    user.fields.username,
                    user.fields.email
                )
                .to_lowercase()
                .contains(&query)
            })
            .copied()
            .collect::<Vec<_>>();
        let mut grid = row().key("member-grid").w_full().flex_wrap().padding(4.0);
        for user in &matching {
            let id = user.id.clone();
            let checked = members.contains(&id);
            let name_text = format!("{} {}", user.fields.given_name, user.fields.family_name);
            let detail = format!(
                "{} · {}",
                user.fields.email,
                if user.fields.active {
                    "active"
                } else {
                    "inactive"
                }
            );
            grid = grid.child(
                el().key(format!("member-row-{id}"))
                    .w_frac(0.5)
                    .padding(4.0)
                    .child(
                        row()
                            .w_full()
                            .gap(12.0)
                            .center_y()
                            .padding(12.0)
                            .radius(6.0)
                            .border(1.0, p.line)
                            .fill(p.card)
                            .child(
                                Checkbox::new(checked)
                                    .label(name_text.clone())
                                    .hide_label()
                                    .disabled(self.busy)
                                    .on_toggle(move |s: &mut Workspace| {
                                        if let Some(Editor::Group { members, .. }) = &mut s.editor {
                                            if members.contains(&id) {
                                                members.retain(|member| member != &id);
                                            } else {
                                                members.push(id.clone());
                                            }
                                            s.editor_dirty = true;
                                        }
                                    })
                                    .build(&ui.k)
                                    .key("member"),
                            )
                            .child(
                                col()
                                    .grow(1.0)
                                    .min_w(0.0)
                                    .child(
                                        font_text(name_text, 13.0, SEMIBOLD, p.text, ui).truncate(),
                                    )
                                    .child(caption(detail, ui).truncate()),
                            ),
                    ),
            );
        }
        if total == 0 {
            grid = grid.child(
                font_text(
                    "Add users to this environment first.",
                    13.0,
                    400.0,
                    p.muted,
                    ui,
                )
                .w_full()
                .padding(12.0),
            );
        }
        col()
            .key("group-form")
            .w_full()
            .gap(16.0)
            .child(field(
                "group-name",
                "Group name",
                "",
                "Study Group",
                name,
                group_name,
                ui,
            ))
            .child(
                col()
                    .w_full()
                    .gap(8.0)
                    .child(font_text("Members", 12.0, 400.0, p.text, ui))
                    .child(
                        row()
                            .w_full()
                            .gap(12.0)
                            .center_y()
                            .child(
                                TextInput::new(search)
                                    .label("Search users")
                                    .placeholder("Search users")
                                    .width(None)
                                    .on_edit(group_search)
                                    .build(&ui.k)
                                    .key("member-search")
                                    .grow(1.0),
                            )
                            .child(
                                font_text(
                                    format!(
                                        "Showing {} of {total} · {} selected",
                                        matching.len(),
                                        members.len()
                                    ),
                                    12.0,
                                    400.0,
                                    p.muted,
                                    ui,
                                )
                                .key("member-count"),
                            ),
                    )
                    .child(
                        col()
                            .key("member-scroll")
                            .w_full()
                            .max_h(300.0)
                            .radius(6.0)
                            .border(1.0, p.line)
                            .fill(p.soft)
                            .clip_rounded(6.0)
                            .scroll(ScrollSpec {
                                stick_bottom: false,
                            })
                            .child(grid),
                    ),
            )
    }

    fn history_entries(&self, entries: &[OperationLog], expanded: &BTreeSet<usize>, ui: &Ui) -> El {
        let p = ui.p;
        let mut list = col().key("history").w_full().gap(12.0);
        if entries.is_empty() {
            list = list.child(font_text(
                "No operations recorded yet.",
                13.0,
                400.0,
                p.muted,
                ui,
            ));
        }
        for (index, entry) in entries.iter().enumerate() {
            let details = [
                format!("{} {} {}", entry.method, entry.path, entry.status),
                entry.request_body.clone(),
                entry.response_body.clone(),
                entry.err.clone(),
            ]
            .into_iter()
            .filter(|value| !value.trim().is_empty())
            .collect::<Vec<_>>();
            let open = expanded.contains(&index);
            let mut card = col()
                .key(format!("history-entry-{index}"))
                .role("group")
                .label(format!("{}: {}", entry.created_at, entry.summary))
                .w_full()
                .gap(8.0)
                .padding(12.0)
                .radius(6.0)
                .border(1.0, p.line)
                .child(
                    row()
                        .gap(8.0)
                        .center_y()
                        .child(caption(entry.created_at.clone(), ui))
                        .child(
                            font_text(entry.kind.to_uppercase(), 10.0, 400.0, p.muted, ui)
                                .px(6.0)
                                .py(2.0)
                                .radius(3.0)
                                .border(1.0, p.line),
                        ),
                )
                .child(
                    font_text(entry.summary.clone(), 13.0, 400.0, p.text, ui)
                        .key("history-summary")
                        .wrap(),
                );
            if !details.is_empty() {
                let label = if open {
                    "Hide request and response"
                } else {
                    "Show request and response"
                };
                card = card.child(
                    row()
                        .key("history-toggle")
                        .role("button")
                        .label(label)
                        .expanded(open)
                        .focusable(true)
                        .gap(6.0)
                        .center_y()
                        .cursor(rune::Cursor::Pointer)
                        .child(
                            icon(
                                if open {
                                    &icons::CHEVRON_DOWN
                                } else {
                                    &icons::CHEVRON_RIGHT
                                },
                                12.0,
                            )
                            .color(p.accent),
                        )
                        .child(font_text(label, 12.0, 400.0, p.accent, ui).a11y_hidden())
                        .on_press(move |s: &mut Workspace| {
                            if let Some(Editor::History { expanded, .. }) = &mut s.editor
                                && !expanded.remove(&index)
                            {
                                expanded.insert(index);
                            }
                        }),
                );
                if open {
                    for (value_index, value) in details.into_iter().enumerate() {
                        card = card.child(
                            font_text(value, 12.0, 400.0, p.text, ui)
                                .key(format!("history-value-{value_index}"))
                                .w_full()
                                .wrap_anywhere()
                                .selectable(true)
                                .padding(8.0)
                                .radius(6.0)
                                .fill(p.soft),
                        );
                    }
                }
            }
            list = list.child(card);
        }
        list
    }
}
