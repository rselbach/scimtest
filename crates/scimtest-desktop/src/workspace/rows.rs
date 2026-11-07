use std::collections::BTreeSet;

use super::{
    DeleteTarget, Editor, Workspace,
    view::{cell, icon, status_pill},
};
use crate::theme::Palette;
use gpui::{Context, IntoElement, SharedString, div, prelude::*, px};
use gpui_component::{
    Disableable, Selectable, StyledExt,
    button::{Button, ButtonVariants},
    checkbox::Checkbox,
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
            .child(cell("name", name.clone()).font_weight(gpui::FontWeight::SEMIBOLD))
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
                    .w(px(110.))
                    .child(if user.fields.active {
                        status_pill("active", palette.success)
                    } else {
                        status_pill("inactive", palette.muted)
                    }),
            )
            .child(
                div()
                    .h_flex()
                    .justify_end()
                    .gap_1()
                    .w(px(110.))
                    .child(self.history_button(DeleteTarget::User, &id, &name, cx))
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
                    .child(self.remove_button(DeleteTarget::User, &id, &name, user.deleted, cx)),
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
                    .font_weight(gpui::FontWeight::SEMIBOLD),
            )
            .child(
                div()
                    .id("members")
                    .role(gpui::Role::Cell)
                    .aria_label(group.fields.member_ids.len().to_string())
                    .w(px(160.))
                    .child(group.fields.member_ids.len().to_string()),
            )
            .child(
                div()
                    .h_flex()
                    .justify_end()
                    .gap_1()
                    .w(px(110.))
                    .child(self.history_button(
                        DeleteTarget::Group,
                        &group.id,
                        &group.fields.display_name,
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
                    .child(self.remove_button(
                        DeleteTarget::Group,
                        &group.id,
                        &group.fields.display_name,
                        group.deleted,
                        cx,
                    )),
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
        let active = self.selected.as_deref() == Some(environment.id.as_str());
        let settings = &environment.settings;
        let mut protocols = div().h_flex().gap_2();
        if settings.supports_oidc() {
            protocols = protocols.child(status_pill("OIDC ✓", palette.success));
        }
        if settings.supports_saml() {
            protocols = protocols.child(status_pill("SAML ✓", palette.success));
        }
        if !settings.supports_oidc() && !settings.supports_saml() {
            protocols = protocols.child(status_pill("Not set up", palette.muted));
        }
        let mut name = div()
            .h_flex()
            .flex_1()
            .min_w_0()
            .gap_3()
            .items_center()
            .child(
                div()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .overflow_hidden()
                    .text_ellipsis()
                    .whitespace_nowrap()
                    .child(environment.name.clone()),
            );
        if active {
            name = name.child(status_pill("Active", palette.success));
        }
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
            .hover(|row| row.bg(palette.accent.opacity(0.04)))
            .child(name)
            .child(div().flex_1().child(protocols))
            .child(
                div()
                    .h_flex()
                    .justify_end()
                    .gap_1()
                    .w(px(150.))
                    .child(
                        Button::new(SharedString::from(format!("activate-{}", environment.id)))
                            .accessibility_label(format!("Use {} as active", environment.name))
                            .icon(icon("icons/circle-check.svg"))
                            .tooltip("Use as active environment")
                            .ghost()
                            .selected(active)
                            .h(px(29.))
                            .disabled(self.busy || active)
                            .on_click(cx.listener({
                                let id = environment.id.clone();
                                move |view, _, _, cx| view.select_environment(id.clone(), cx)
                            })),
                    )
                    .child(
                        Button::new(SharedString::from(format!("edit-{}", environment.id)))
                            .accessibility_label(format!("Edit {}", environment.name))
                            .icon(icon("icons/edit.svg"))
                            .tooltip("Set up environment")
                            .ghost()
                            .h(px(29.))
                            .disabled(self.busy)
                            .on_click(cx.listener({
                                let environment = environment.clone();
                                move |view, _, window, cx| {
                                    view.edit_environment(Some(&environment), window, cx)
                                }
                            })),
                    )
                    .child(
                        Button::new(SharedString::from(format!("delete-{}", environment.id)))
                            .accessibility_label(format!("Delete {}", environment.name))
                            .icon(icon("icons/trash.svg"))
                            .tooltip("Delete environment")
                            .ghost()
                            .h(px(29.))
                            .disabled(self.busy)
                            .on_click(cx.listener({
                                let id = environment.id.clone();
                                let name = environment.name.clone();
                                move |view, _, _, cx| {
                                    view.editor = Some(Editor::Delete {
                                        target: DeleteTarget::Environment,
                                        id: id.clone(),
                                        name: name.clone(),
                                    });
                                    cx.notify();
                                }
                            })),
                    ),
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

    fn history_button(
        &self,
        target: DeleteTarget,
        id: &str,
        name: &str,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let id = id.to_owned();
        let name = name.to_owned();
        Button::new(SharedString::from(format!("history-{id}")))
            .accessibility_label(format!("History for {name}"))
            .icon(icon("icons/history.svg"))
            .tooltip("History")
            .ghost()
            .h(px(29.))
            .disabled(self.busy)
            .on_click(cx.listener(move |view, _, _, cx| {
                let entries = view
                    .directory()
                    .and_then(|directory| match target {
                        DeleteTarget::User => directory.user_operations.get(&id),
                        _ => directory.group_operations.get(&id),
                    })
                    .cloned()
                    .unwrap_or_default();
                view.editor = Some(Editor::History {
                    noun: match target {
                        DeleteTarget::User => "User",
                        _ => "Group",
                    },
                    name: name.clone(),
                    entries,
                    expanded: BTreeSet::new(),
                });
                cx.notify();
            }))
    }

    /// Deletes a live entry, or restores it when it is already deleted.
    fn remove_button(
        &self,
        target: DeleteTarget,
        id: &str,
        name: &str,
        deleted: bool,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let id = id.to_owned();
        let name = name.to_owned();
        let button = Button::new(SharedString::from(format!("remove-{id}")))
            .ghost()
            .h(px(29.))
            .disabled(self.busy);
        if deleted {
            return button
                .accessibility_label(format!("Restore {name}"))
                .icon(icon("icons/restore.svg"))
                .tooltip("Restore")
                .on_click(cx.listener(move |view, _, _, cx| {
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
                }));
        }
        button
            .accessibility_label(format!("Delete {name}"))
            .icon(icon("icons/trash.svg"))
            .tooltip(match target {
                DeleteTarget::User => "Delete user",
                _ => "Delete group",
            })
            .on_click(cx.listener(move |view, _, _, cx| {
                view.editor = Some(Editor::Delete {
                    target,
                    id: id.clone(),
                    name: name.clone(),
                });
                cx.notify();
            }))
    }
}
