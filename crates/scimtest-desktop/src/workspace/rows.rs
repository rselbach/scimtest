use std::collections::BTreeSet;

use rune::{El, Icon, el, row};
use rune_kit::{Checkbox, IconButton, IconButtonVariant};
use scimtest_core::model::*;

use super::{
    DeleteTarget, Editor, Workspace,
    table::cell,
    view::{font_text, status_pill},
};
use crate::{
    icons,
    theme::{SEMIBOLD, Ui},
};

fn row_frame(key: String, name: &str, height: f32, ui: &Ui) -> El {
    row()
        .key(key)
        .role("row")
        .label(name.to_owned())
        .w_full()
        .h(height)
        .px(16.0)
        .gap(16.0)
        .center_y()
        .hover(ui.p.accent.alpha(0.04))
}

fn action(
    key: String,
    glyph: &'static Icon,
    label: String,
    help: &'static str,
    disabled: bool,
    press: impl Fn(&mut Workspace) + 'static,
    ui: &Ui,
) -> El {
    IconButton::new(glyph)
        .variant(IconButtonVariant::Ghost)
        .label(label)
        .help(help)
        .disabled(disabled)
        .on_press(press)
        .build(&ui.k)
        .key(key)
}

fn actions(width: f32) -> El {
    row().w(width).gap(4.0).justify_end().center_y()
}

impl Workspace {
    pub(super) fn user_row(&self, user: &User, ui: &Ui) -> El {
        let p = ui.p;
        let name = format!("{} {}", user.fields.given_name, user.fields.family_name);
        let edited = user.clone();
        let open = user.clone();
        let mut body = row_frame(user.id.clone(), &name, 51.0, ui)
            .child(self.selection_checkbox(&user.id, &name, user.deleted, ui))
            .child(cell("name", name.clone(), ui).font(ui.font(13.0, SEMIBOLD)))
            .child(cell("username", user.fields.username.clone(), ui))
            .child(cell("email", user.fields.email.clone(), ui))
            .child(
                el().key("active")
                    .role("cell")
                    .label(if user.fields.active {
                        "Active"
                    } else {
                        "Inactive"
                    })
                    .w(110.0)
                    .child(if user.fields.active {
                        status_pill("active", p.success, ui)
                    } else {
                        status_pill("inactive", p.muted, ui)
                    }),
            )
            .child(
                actions(110.0)
                    .child(self.history_button(DeleteTarget::User, &user.id, &name, ui))
                    .child(action(
                        format!("edit-{}", user.id),
                        &icons::EDIT,
                        format!("Edit {name}"),
                        "Edit user",
                        self.busy || user.deleted,
                        move |s: &mut Workspace| s.edit_user(Some(&edited)),
                        ui,
                    ))
                    .child(self.remove_button(
                        DeleteTarget::User,
                        &user.id,
                        &name,
                        user.deleted,
                        ui,
                    )),
            );
        if !self.busy && !user.deleted {
            body = body.on_double_press(move |s: &mut Workspace| s.edit_user(Some(&open)));
        }
        body
    }

    pub(super) fn group_row(&self, group: &Group, ui: &Ui) -> El {
        let name = group.fields.display_name.clone();
        let edited = group.clone();
        let open = group.clone();
        let members = group.fields.member_ids.len().to_string();
        let mut body = row_frame(group.id.clone(), &name, 51.0, ui)
            .child(self.selection_checkbox(&group.id, &name, group.deleted, ui))
            .child(cell("name", name.clone(), ui).font(ui.font(13.0, SEMIBOLD)))
            .child(
                font_text(members.clone(), 13.0, 400.0, ui.p.text, ui)
                    .key("members")
                    .role("cell")
                    .label(members)
                    .w(160.0),
            )
            .child(
                actions(110.0)
                    .child(self.history_button(DeleteTarget::Group, &group.id, &name, ui))
                    .child(action(
                        format!("edit-{}", group.id),
                        &icons::EDIT,
                        format!("Edit {name}"),
                        "Edit group",
                        self.busy || group.deleted,
                        move |s: &mut Workspace| s.edit_group(Some(&edited)),
                        ui,
                    ))
                    .child(self.remove_button(
                        DeleteTarget::Group,
                        &group.id,
                        &name,
                        group.deleted,
                        ui,
                    )),
            );
        if !self.busy && !group.deleted {
            body = body.on_double_press(move |s: &mut Workspace| s.edit_group(Some(&open)));
        }
        body
    }

    pub(super) fn environment_row(&self, directory: &Directory, ui: &Ui) -> El {
        let p = ui.p;
        let environment = &directory.environment;
        let active = self.selected.as_deref() == Some(environment.id.as_str());
        let settings = &environment.settings;
        let mut protocols = row().gap(8.0).center_y();
        if settings.supports_oidc() {
            protocols = protocols.child(status_pill("OIDC ✓", p.success, ui));
        }
        if settings.supports_saml() {
            protocols = protocols.child(status_pill("SAML ✓", p.success, ui));
        }
        if !settings.supports_oidc() && !settings.supports_saml() {
            protocols = protocols.child(status_pill("Not set up", p.muted, ui));
        }
        let mut name = row()
            .key("name")
            .role("cell")
            .label(environment.name.clone())
            .grow(1.0)
            .min_w(0.0)
            .gap(12.0)
            .center_y()
            .child(
                font_text(environment.name.clone(), 13.0, SEMIBOLD, p.text, ui)
                    .truncate()
                    .shrink(),
            );
        if active {
            name = name.child(status_pill("Active", p.success, ui));
        }
        let id = environment.id.clone();
        let edited = environment.clone();
        let deleted = (environment.id.clone(), environment.name.clone());
        row_frame(environment.id.clone(), &environment.name, 59.0, ui)
            .child(name)
            .child(
                el().key("protocol")
                    .role("cell")
                    .grow(1.0)
                    .min_w(0.0)
                    .child(protocols),
            )
            .child(
                actions(150.0)
                    .child(action(
                        format!("activate-{}", environment.id),
                        &icons::CIRCLE_CHECK,
                        format!("Use {} as active", environment.name),
                        "Use as active environment",
                        self.busy || active,
                        move |s: &mut Workspace| s.select_environment(id.clone()),
                        ui,
                    ))
                    .child(action(
                        format!("edit-{}", environment.id),
                        &icons::EDIT,
                        format!("Edit {}", environment.name),
                        "Set up environment",
                        self.busy,
                        move |s: &mut Workspace| s.edit_environment(Some(&edited)),
                        ui,
                    ))
                    .child(action(
                        format!("delete-{}", environment.id),
                        &icons::TRASH,
                        format!("Delete {}", environment.name),
                        "Delete environment",
                        self.busy,
                        move |s: &mut Workspace| {
                            s.open_editor(Editor::Delete {
                                target: DeleteTarget::Environment,
                                id: deleted.0.clone(),
                                name: deleted.1.clone(),
                            })
                        },
                        ui,
                    )),
            )
    }

    fn selection_checkbox(&self, id: &str, name: &str, deleted: bool, ui: &Ui) -> El {
        let checked = self.selected_rows.contains(id);
        let key = format!("select-{id}");
        let id = id.to_owned();
        el().w(20.0).child(
            Checkbox::new(checked)
                .label(format!("Select {name}"))
                .hide_label()
                .disabled(self.busy || deleted)
                .on_toggle(move |s: &mut Workspace| {
                    if !s.selected_rows.remove(&id) {
                        s.selected_rows.insert(id.clone());
                    }
                })
                .build(&ui.k)
                .key(key),
        )
    }

    fn history_button(&self, target: DeleteTarget, id: &str, name: &str, ui: &Ui) -> El {
        let key = format!("history-{id}");
        let id = id.to_owned();
        let shown = name.to_owned();
        action(
            key,
            &icons::HISTORY,
            format!("History for {name}"),
            "History",
            self.busy,
            move |s: &mut Workspace| {
                let entries = s
                    .directory()
                    .and_then(|directory| match target {
                        DeleteTarget::User => directory.user_operations.get(&id),
                        _ => directory.group_operations.get(&id),
                    })
                    .cloned()
                    .unwrap_or_default();
                s.open_editor(Editor::History {
                    noun: match target {
                        DeleteTarget::User => "User",
                        _ => "Group",
                    },
                    name: shown.clone(),
                    entries,
                    expanded: BTreeSet::new(),
                });
            },
            ui,
        )
    }

    /// Deletes a live entry, or restores it when it is already deleted.
    fn remove_button(
        &self,
        target: DeleteTarget,
        id: &str,
        name: &str,
        deleted: bool,
        ui: &Ui,
    ) -> El {
        let key = format!("remove-{id}");
        let id = id.to_owned();
        let shown = name.to_owned();
        if deleted {
            return action(
                key,
                &icons::RESTORE,
                format!("Restore {name}"),
                "Restore",
                self.busy,
                move |s: &mut Workspace| {
                    let environment = s.selected.clone().unwrap_or_default();
                    let id = id.clone();
                    s.command(move |store| {
                        match target {
                            DeleteTarget::User => {
                                store.restore_user(&environment, &id)?;
                            }
                            _ => {
                                store.restore_group(&environment, &id)?;
                            }
                        }
                        Ok(("Restored".into(), None))
                    });
                },
                ui,
            );
        }
        action(
            key,
            &icons::TRASH,
            format!("Delete {name}"),
            match target {
                DeleteTarget::User => "Delete user",
                _ => "Delete group",
            },
            self.busy,
            move |s: &mut Workspace| {
                s.open_editor(Editor::Delete {
                    target,
                    id: id.clone(),
                    name: shown.clone(),
                })
            },
            ui,
        )
    }
}
