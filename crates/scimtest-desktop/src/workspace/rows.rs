use super::{
    DeleteTarget, Editor, Workspace,
    view::{cell, icon},
};
use crate::dropdown::DropdownMenu;
use crate::theme::Palette;
use gpui::{Context, Div, IntoElement, SharedString, div, prelude::*, px};
use gpui_component::{
    Disableable, StyledExt,
    button::{Button, ButtonVariants},
    checkbox::Checkbox,
    menu::PopupMenuItem,
};
use scimtest_core::model::*;

impl Workspace {
    pub(super) fn user_row(&self, user: &User, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let palette = Palette::get(cx);
        let edit_user = user.clone();
        let id = user.id.clone();
        let row_id = user.id.clone();
        let name = format!("{} {}", user.fields.given_name, user.fields.family_name);
        let body = div()
            .id(SharedString::from(user.id.clone()))
            .role(gpui::Role::Row)
            .aria_label(name.clone())
            .h_flex()
            .h(px(51.))
            .flex_shrink_0()
            .px_4()
            .gap_4()
            .border_b_1()
            .border_color(palette.line.opacity(0.7))
            .hover(|row| row.bg(palette.accent.opacity(0.04)))
            .child(self.selection_checkbox(&id, &name, user.deleted, cx))
            .child(cell("name", name.clone()).font_weight(gpui::FontWeight::MEDIUM))
            .child(cell("username", user.fields.username.clone()))
            .child(cell("email", user.fields.email.clone()))
            .child(
                div()
                    .id("active")
                    .role(gpui::Role::Cell)
                    .aria_label(if user.fields.active {
                        "Active"
                    } else {
                        "Inactive"
                    })
                    .w(px(98.))
                    .child(
                        div()
                            .h_flex()
                            .gap_1()
                            .px_2()
                            .py_1()
                            .rounded_full()
                            .bg(if user.fields.active {
                                palette.success_bg
                            } else {
                                palette.soft
                            })
                            .text_color(if user.fields.active {
                                palette.success
                            } else {
                                palette.muted
                            })
                            .text_size(px(11.))
                            .child(if user.fields.active {
                                "●  active"
                            } else {
                                "○  inactive"
                            }),
                    ),
            )
            .child(sync_badge(
                user.deleted,
                user.dirty,
                &user.last_error,
                &user.remote_id,
                palette,
            ))
            .child(
                div()
                    .h_flex()
                    .justify_end()
                    .gap_1()
                    .w(px(96.))
                    .child(self.resource_menu(
                        DeleteTarget::User,
                        &id,
                        &name,
                        user.deleted,
                        Some(user.fields.active),
                        cx,
                    ))
                    .child(
                        Button::new(SharedString::from(format!("edit-{id}")))
                            .accessibility_label(format!("Edit {name}"))
                            .icon(icon("icons/edit.svg"))
                            .tooltip("Edit user")
                            .ghost()
                            .h(px(29.))
                            .disabled(self.busy || user.deleted)
                            .on_click(cx.listener(move |view, _, window, cx| {
                                view.edit_user(Some(&edit_user), window, cx)
                            })),
                    )
                    .child(
                        Button::new(SharedString::from(format!("delete-{id}")))
                            .accessibility_label(format!("Delete {name}"))
                            .icon(icon("icons/trash.svg"))
                            .tooltip("Delete user")
                            .ghost()
                            .h(px(29.))
                            .disabled(self.busy || user.deleted)
                            .on_click(cx.listener(move |view, _, _, cx| {
                                view.editor = Some(Editor::Delete {
                                    target: DeleteTarget::User,
                                    id: id.clone(),
                                    name: name.clone(),
                                });
                                cx.notify();
                            })),
                    ),
            );
        super::row_focus::Row {
            id: row_id,
            body,
            scroll: self.table_scroll.clone(),
        }
    }

    pub(super) fn group_row(
        &self,
        group: &Group,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let palette = Palette::get(cx);
        let group = group.clone();
        let edited = group.clone();
        let row_id = group.id.clone();
        let body = div()
            .id(SharedString::from(group.id.clone()))
            .role(gpui::Role::Row)
            .aria_label(group.fields.display_name.clone())
            .h_flex()
            .h(px(51.))
            .flex_shrink_0()
            .px_4()
            .gap_4()
            .border_b_1()
            .border_color(palette.line.opacity(0.7))
            .hover(|row| row.bg(palette.accent.opacity(0.04)))
            .child(self.selection_checkbox(
                &group.id,
                &group.fields.display_name,
                group.deleted,
                cx,
            ))
            .child(
                cell("name", group.fields.display_name.clone())
                    .font_weight(gpui::FontWeight::MEDIUM),
            )
            .child(cell("members", group.fields.member_ids.len().to_string()))
            .child(sync_badge(
                group.deleted,
                group.dirty,
                &group.last_error,
                &group.remote_id,
                palette,
            ))
            .child(
                div()
                    .h_flex()
                    .justify_end()
                    .gap_1()
                    .w(px(96.))
                    .child(self.resource_menu(
                        DeleteTarget::Group,
                        &group.id,
                        &group.fields.display_name,
                        group.deleted,
                        None,
                        cx,
                    ))
                    .child(
                        Button::new(SharedString::from(format!("edit-{}", group.id)))
                            .accessibility_label(format!("Edit {}", group.fields.display_name))
                            .icon(icon("icons/edit.svg"))
                            .tooltip("Edit group")
                            .ghost()
                            .h(px(29.))
                            .disabled(self.busy || group.deleted)
                            .on_click(cx.listener(move |view, _, window, cx| {
                                view.edit_group(Some(&edited), window, cx)
                            })),
                    )
                    .child(
                        Button::new(SharedString::from(format!("delete-{}", group.id)))
                            .accessibility_label(format!("Delete {}", group.fields.display_name))
                            .icon(icon("icons/trash.svg"))
                            .tooltip("Delete group")
                            .ghost()
                            .h(px(29.))
                            .disabled(self.busy || group.deleted)
                            .on_click(cx.listener(move |view, _, _, cx| {
                                view.editor = Some(Editor::Delete {
                                    target: DeleteTarget::Group,
                                    id: group.id.clone(),
                                    name: group.fields.display_name.clone(),
                                });
                                cx.notify();
                            })),
                    ),
            );
        super::row_focus::Row {
            id: row_id,
            body,
            scroll: self.table_scroll.clone(),
        }
    }

    pub(super) fn environment_row(
        &self,
        directory: &Directory,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let palette = Palette::get(cx);
        let environment = directory.environment.clone();
        let row_id = environment.id.clone();
        let body = div()
            .id(SharedString::from(environment.id.clone()))
            .role(gpui::Role::Row)
            .aria_label(environment.name.clone())
            .h_flex()
            .h(px(59.))
            .flex_shrink_0()
            .px_4()
            .gap_4()
            .border_b_1()
            .border_color(palette.line.opacity(0.7))
            .child(cell("name", environment.name.clone()).font_weight(gpui::FontWeight::MEDIUM))
            .child(cell("endpoint", environment.slug.clone()).text_color(palette.muted))
            .child(
                div()
                    .id("users")
                    .role(gpui::Role::Cell)
                    .aria_label(directory.users.len().to_string())
                    .w(px(65.))
                    .child(directory.users.len().to_string()),
            )
            .child(
                div()
                    .id("groups")
                    .role(gpui::Role::Cell)
                    .aria_label(directory.groups.len().to_string())
                    .w(px(65.))
                    .child(directory.groups.len().to_string()),
            )
            .child(
                Button::new(SharedString::from(format!("setup-{}", environment.id)))
                    .accessibility_label(format!("Set up {}", environment.name))
                    .label("Set up")
                    .h(px(29.))
                    .disabled(self.busy)
                    .on_click(cx.listener(move |view, _, window, cx| {
                        view.edit_environment(Some(&environment), window, cx)
                    })),
            );
        super::row_focus::Row {
            id: row_id,
            body,
            scroll: self.table_scroll.clone(),
        }
    }

    pub(super) fn selection_checkbox(
        &self,
        id: &str,
        name: &str,
        deleted: bool,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let id = id.to_owned();
        div().w(px(20.)).flex_shrink_0().child(
            Checkbox::new(SharedString::from(format!("select-{id}")))
                .accessibility_label(format!("Select {name}"))
                .checked(self.selected_rows.contains(&id))
                .disabled(self.busy || deleted)
                .on_click(cx.listener(move |view, checked: &bool, _, cx| {
                    if *checked {
                        view.selected_rows.insert(id.clone());
                    } else {
                        view.selected_rows.remove(&id);
                    }
                    cx.notify();
                })),
        )
    }

    fn resource_menu(
        &self,
        target: DeleteTarget,
        id: &str,
        name: &str,
        deleted: bool,
        active: Option<bool>,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let id = id.to_owned();
        let name = name.to_owned();
        let scim = self
            .directory()
            .is_some_and(|directory| directory.environment.settings.scim_enabled);
        let view = cx.weak_entity();
        Button::new(SharedString::from(format!("more-{id}")))
            .accessibility_label(format!("Actions for {name}"))
            .label("···")
            .tooltip("More actions")
            .ghost()
            .h(px(29.))
            .disabled(self.busy)
            .dropdown_menu(move |mut menu, _, _| {
                let history_view = view.clone();
                let history_id = id.clone();
                let name = name.clone();
                menu = menu.item(PopupMenuItem::new("History").on_click(move |_, _, cx| {
                    let _ = history_view.update(cx, |view, cx| {
                        let entries = view
                            .directory()
                            .and_then(|directory| match target {
                                DeleteTarget::User => directory.user_operations.get(&history_id),
                                _ => directory.group_operations.get(&history_id),
                            })
                            .cloned()
                            .unwrap_or_default();
                        view.editor = Some(Editor::History {
                            name: name.clone(),
                            entries,
                        });
                        cx.notify();
                    });
                }));
                if scim {
                    let view = view.clone();
                    let id = id.clone();
                    menu = menu.item(PopupMenuItem::new("Push to SCIM").on_click(
                        move |_, _, cx| {
                            let _ = view.update(cx, |view, cx| {
                                view.tab = super::Tab::Scim;
                                let kind = if matches!(target, DeleteTarget::User) {
                                    "user"
                                } else {
                                    "group"
                                };
                                view.scim_action("push", Some((kind.into(), id.clone())), cx);
                            });
                        },
                    ));
                }
                if deleted {
                    let view = view.clone();
                    let id = id.clone();
                    menu = menu.item(PopupMenuItem::new("Restore").on_click(move |_, _, cx| {
                        let _ = view.update(cx, |view, cx| {
                            let environment = view.selected.clone().unwrap_or_default();
                            let id = id.clone();
                            view.command(
                                move |store| {
                                    match target {
                                        DeleteTarget::User => {
                                            store.restore_user(&environment, &id)?;
                                        }
                                        _ => {
                                            store.restore_group(&environment, &id)?;
                                        }
                                    }
                                    Ok(("Restored".into(), None))
                                },
                                cx,
                            );
                        });
                    }));
                } else if let Some(active) = active {
                    let view = view.clone();
                    let id = id.clone();
                    menu = menu.item(
                        PopupMenuItem::new(if active { "Deactivate" } else { "Activate" })
                            .on_click(move |_, _, cx| {
                                let _ = view.update(cx, |view, cx| {
                                    let environment = view.selected.clone().unwrap_or_default();
                                    let id = id.clone();
                                    view.command(
                                        move |store| {
                                            store.update_user(
                                                &environment,
                                                &id,
                                                UserPatch {
                                                    active: Some(!active),
                                                    ..Default::default()
                                                },
                                            )?;
                                            Ok((
                                                if active { "Deactivated" } else { "Activated" }
                                                    .into(),
                                                None,
                                            ))
                                        },
                                        cx,
                                    );
                                });
                            }),
                    );
                }
                menu
            })
    }
}

fn sync_badge(
    deleted: bool,
    dirty: bool,
    error: &str,
    remote: &str,
    palette: Palette,
) -> gpui::Stateful<Div> {
    let (label, color) = if deleted {
        ("Deleted", palette.danger)
    } else if !error.is_empty() {
        ("Error", palette.danger)
    } else if dirty {
        ("Pending", palette.accent)
    } else if !remote.is_empty() {
        ("Synced", palette.success)
    } else {
        ("Local", palette.muted)
    };
    div()
        .id("sync")
        .role(gpui::Role::Cell)
        .aria_label(format!("Sync: {label}"))
        .w(px(78.))
        .text_size(px(11.))
        .text_color(color)
        .child(label)
}
