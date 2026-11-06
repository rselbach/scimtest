use crate::dropdown::DropdownMenu;
use gpui::{Context, IntoElement, MouseButton, div, prelude::*, px, rgba};
use gpui_component::{
    Disableable, FocusTrapElement, StyledExt,
    button::{Button, ButtonVariants},
    checkbox::Checkbox,
    input::{Input, Textarea},
    menu::PopupMenuItem,
    scroll::ScrollableElement,
};

use super::{DeleteTarget, Editor, Workspace};
use crate::theme::Palette;

pub(super) fn field(
    label: &'static str,
    state: &gpui::Entity<gpui_component::input::InputState>,
) -> impl IntoElement {
    div()
        .v_flex()
        .flex_1()
        .min_w_0()
        .gap_2()
        .child(div().text_size(px(12.)).child(label))
        .child(Input::new(state).aria_label(label))
}

impl Workspace {
    pub(super) fn editor(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = Palette::get(cx);
        let Some(editor) = &self.editor else {
            return div().into_any_element();
        };
        let title = match editor {
            Editor::Lifecycle(_) => "Run a lifecycle scenario",
            Editor::Faults(_) => "Custom faults",
            Editor::Environment { id: Some(_), .. } => "Environment settings",
            Editor::Environment { .. } => "Add environment",
            Editor::User { id: Some(_), .. } => "Edit user",
            Editor::User { .. } => "Add user",
            Editor::Group { id: Some(_), .. } => "Edit group",
            Editor::Group { .. } => "Add group",
            Editor::Delete { .. } => "Confirm deletion",
            Editor::BulkDelete { .. } => "Delete selected entries",
            Editor::History { .. } => "Operation history",
            Editor::RestoreBackup { .. } => "Restore environment backup",
            Editor::CreateUsers { .. } => "Create users",
            Editor::ConfirmTool {
                action: "clear-local",
            } => "Clear local directory",
            Editor::ConfirmTool { .. } => "Delete all users",
        };
        let mut body = div().v_flex().gap_5().p_5();
        let mut deletion = None;
        match editor {
            Editor::Lifecycle(form) => body = body.child(form.fields(self, cx)),
            Editor::Faults(form) => body = body.child(form.fields(self.busy, cx)),
            Editor::Environment {
                id,
                name,
                slug,
                settings,
            } => {
                body = body.child(settings.tabs(cx));
                if let Some(id) = id {
                    let copy_id = id.clone();
                    let save_id = id.clone();
                    body = body.child(
                        div()
                            .h_flex()
                            .gap_2()
                            .child(
                                Button::new("copy-connection")
                                    .label("Copy config JSON")
                                    .disabled(self.busy)
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.export_connection(copy_id.clone(), false, cx)
                                    })),
                            )
                            .child(
                                Button::new("save-connection")
                                    .label("Save config JSON…")
                                    .disabled(self.busy)
                                    .on_click(cx.listener(move |view, _, _, cx| {
                                        view.export_connection(save_id.clone(), true, cx)
                                    })),
                            ),
                    );
                }
                if settings.section == super::environment::Section::General {
                    body = body
                        .child(field("Environment name", name))
                        .child(field("Endpoint name", slug));
                }
                body = body.child(settings.fields(self.busy, cx));
                if let Some(id) = id {
                    deletion = Some((
                        DeleteTarget::Environment,
                        id.clone(),
                        name.read(cx).value().to_string(),
                    ));
                }
            }
            Editor::User {
                id,
                fields,
                active,
                manager,
                attributes,
                ..
            } => {
                body = body
                    .child(
                        div()
                            .h_flex()
                            .items_start()
                            .gap_4()
                            .child(field("Username", &fields[3]))
                            .child(field("Email", &fields[2])),
                    )
                    .child(
                        div()
                            .h_flex()
                            .items_start()
                            .gap_4()
                            .child(field("Given name", &fields[0]))
                            .child(field("Family name", &fields[1])),
                    )
                    .child(
                        Checkbox::new("user-active")
                            .label("Active")
                            .checked(*active)
                            .disabled(self.busy)
                            .on_click(cx.listener(|view, checked: &bool, _, cx| {
                                if let Some(Editor::User { active, .. }) = &mut view.editor {
                                    *active = *checked;
                                    view.editor_dirty = true;
                                }
                                cx.notify();
                            })),
                    );
                body = body.child(
                    div()
                        .text_size(px(12.))
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .child("Enterprise attributes"),
                );
                for (labels, indexes) in [
                    (["Employee number", "Cost center"], [4, 5]),
                    (["Organization", "Division"], [6, 7]),
                ] {
                    body = body.child(
                        div()
                            .h_flex()
                            .gap_4()
                            .items_start()
                            .child(field(labels[0], &fields[indexes[0]]))
                            .child(field(labels[1], &fields[indexes[1]])),
                    );
                }
                let manager_name = self
                    .directory()
                    .and_then(|directory| directory.users.iter().find(|user| user.id == *manager))
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
                            .filter(|user| !user.deleted && Some(&user.id) != id.as_ref())
                            .map(|user| {
                                (
                                    user.id.clone(),
                                    format!(
                                        "{} {}",
                                        user.fields.given_name, user.fields.family_name
                                    ),
                                )
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let view = cx.weak_entity();
                body = body.child(
                    div()
                        .h_flex()
                        .items_start()
                        .gap_4()
                        .child(field("Department", &fields[8]))
                        .child(
                            div()
                                .v_flex()
                                .flex_1()
                                .min_w_0()
                                .gap_2()
                                .child(div().text_size(px(12.)).child("Manager"))
                                .child(
                                    Button::new("manager-picker")
                                        .accessibility_label(format!("Manager: {manager_name}"))
                                        .label(manager_name)
                                        .icon(
                                            gpui_component::Icon::default()
                                                .path("icons/chevron-down.svg"),
                                        )
                                        .justify_between()
                                        .border_1()
                                        .border_color(palette.line)
                                        .rounded_md()
                                        .disabled(self.busy)
                                        .dropdown_menu(move |mut menu, _, _| {
                                            for (id, name) in std::iter::once((
                                                String::new(),
                                                "No manager".into(),
                                            ))
                                            .chain(candidates.clone())
                                            {
                                                let view = view.clone();
                                                menu =
                                                    menu.item(PopupMenuItem::new(name).on_click(
                                                        move |_, _, cx| {
                                                            let _ = view.update(cx, |view, cx| {
                                                                if let Some(Editor::User {
                                                                    manager,
                                                                    ..
                                                                }) = &mut view.editor
                                                                {
                                                                    *manager = id.clone();
                                                                    view.editor_dirty = true;
                                                                }
                                                                cx.notify();
                                                            });
                                                        },
                                                    ));
                                            }
                                            menu
                                        }),
                                ),
                        ),
                );
                body = body.child(
                    div()
                        .v_flex()
                        .gap_2()
                        .child("Custom attributes (one name=value per line)")
                        .child(
                            Textarea::new(attributes)
                                .aria_label("Custom attributes (one name=value per line)"),
                        ),
                );
                if let Some(id) = id {
                    deletion = Some((
                        DeleteTarget::User,
                        id.clone(),
                        fields[0].read(cx).value().to_string(),
                    ));
                }
            }
            Editor::Group { id, name, members } => {
                body = body
                    .child(field("Group name", name))
                    .child(div().text_size(px(12.)).child("Members"));
                let mut choices = div().v_flex().gap_2().p_3();
                if let Some(directory) = self.directory() {
                    for user in directory.users.iter().filter(|user| !user.deleted) {
                        let id = user.id.clone();
                        choices = choices.child(
                            div()
                                .id(gpui::SharedString::from(format!("member-row-{id}")))
                                .flex_none()
                                .child(
                                    Checkbox::new(gpui::SharedString::from(format!("member-{id}")))
                                        .label(format!(
                                            "{} {}",
                                            user.fields.given_name, user.fields.family_name
                                        ))
                                        .checked(members.contains(&id))
                                        .disabled(self.busy)
                                        .on_click(cx.listener(
                                            move |view, checked: &bool, _, cx| {
                                                if let Some(Editor::Group { members, .. }) =
                                                    &mut view.editor
                                                {
                                                    members.retain(|member| member != &id);
                                                    if *checked {
                                                        members.push(id.clone());
                                                    }
                                                    view.editor_dirty = true;
                                                }
                                                cx.notify();
                                            },
                                        )),
                                ),
                        );
                    }
                    if directory.users.is_empty() {
                        choices = choices.child(
                            div()
                                .text_color(palette.muted)
                                .child("Add users to this environment first."),
                        );
                    }
                }
                body = body.child(gpui_base::ScrollBounce::new(
                    "member-bounce",
                    &self.member_scroll,
                    choices
                        .id("member-scroll")
                        .max_h(px(230.))
                        .border_1()
                        .border_color(palette.line)
                        .rounded_md()
                        .bg(palette.soft)
                        .overflow_y_scroll()
                        .track_scroll(&self.member_scroll)
                        .vertical_scrollbar(&self.member_scroll),
                ));
                if let Some(id) = id {
                    deletion = Some((
                        DeleteTarget::Group,
                        id.clone(),
                        name.read(cx).value().to_string(),
                    ));
                }
            }
            Editor::Delete { target, name, .. } => {
                body = body
                    .child(div().font_weight(gpui::FontWeight::MEDIUM).child(
                        super::view::accessible_text("delete-question", format!("Delete {name}?")),
                    ))
                    .child(
                        div()
                            .text_color(palette.muted)
                            .child(super::view::accessible_text(
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
                            )),
                    );
            }
            Editor::CreateUsers { count, domain } => {
                body = body
                    .child(field("Number of users (1–10000)", count))
                    .child(field("Email domain", domain));
            }
            Editor::ConfirmTool { action } => {
                body = body.child(div().child(super::view::accessible_text("tool-question",if *action == "clear-local" {
                    "Remove all local users, groups, sync state, and operation history? Remote resources stay in place."
                } else { "Delete every user in this environment? Users tracked by SCIM remain available to restore until their remote deletion completes." })));
            }
            Editor::RestoreBackup { backup } => {
                body = body.child(div().child(super::view::accessible_text("restore-question",format!("Restore the backup from {}? It contains {} user{} and {} group{}.", backup.exported_at, backup.state.users.len(), if backup.state.users.len() == 1 { "" } else { "s" }, backup.state.groups.len(), if backup.state.groups.len() == 1 { "" } else { "s" }))))
                    .child(div().text_color(palette.muted).child(super::view::accessible_text("restore-detail","This replaces the selected environment. A safety copy of the current state will be saved first.")));
            }
            Editor::BulkDelete { ids, .. } => {
                body = body.child(div().child(super::view::accessible_text("delete-question",format!("Delete {} selected {}?", ids.len(), if ids.len() == 1 { "entry" } else { "entries" }))))
                    .child(div().text_color(palette.muted).child(super::view::accessible_text("delete-detail",if self.directory().is_some_and(|directory| directory.tracks_scim()) {
                        "Entries remain available to restore until their remote deletion completes."
                    } else { "This removes the selected entries from this directory." })));
            }
            Editor::History { name, entries } => {
                body = body.child(
                    div()
                        .font_weight(gpui::FontWeight::MEDIUM)
                        .child(name.clone()),
                );
                if entries.is_empty() {
                    body = body.child(
                        div()
                            .text_color(palette.muted)
                            .child("No operations recorded yet."),
                    );
                }
                for (index, entry) in entries.iter().enumerate() {
                    let mut row = div()
                        .id(("history-entry", index))
                        .role(gpui::Role::Group)
                        .aria_label(format!("{}: {}", entry.created_at, entry.summary))
                        .v_flex()
                        .gap_2()
                        .py_3()
                        .border_b_1()
                        .border_color(palette.line)
                        .child(
                            div()
                                .h_flex()
                                .gap_3()
                                .child(div().flex_1().child(entry.summary.clone()))
                                .child(
                                    div()
                                        .text_color(palette.muted)
                                        .text_size(px(11.))
                                        .child(entry.created_at.clone()),
                                ),
                        );
                    for (index, value) in [
                        format!("{} {} {}", entry.method, entry.path, entry.status),
                        entry.request_body.clone(),
                        entry.response_body.clone(),
                        entry.err.clone(),
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        if !value.trim().is_empty() {
                            row = row.child(div().text_size(px(12.)).whitespace_normal().child(
                                super::view::accessible_text(("history-value", index), value),
                            ));
                        }
                    }
                    body = body.child(row);
                }
            }
        }
        if self.failed
            && !self.message.is_empty()
            && !matches!(editor, Editor::Faults(_) | Editor::Lifecycle(_))
        {
            body = body.child(
                super::view::accessible_status(
                    ("editor-error", self.status_revision),
                    self.message.clone(),
                    true,
                )
                .text_color(palette.danger)
                .child(self.message.clone()),
            );
        }
        let mut footer = div()
            .h_flex()
            .gap_2()
            .px_5()
            .py_4()
            .border_t_1()
            .border_color(palette.line);
        if let Some((target, id, name)) = deletion {
            footer = footer.child(
                Button::new("delete")
                    .label("Delete…")
                    .h(px(29.))
                    .ghost()
                    .text_color(palette.danger)
                    .disabled(self.busy)
                    .on_click(cx.listener(move |view, _, _, cx| {
                        view.editor = Some(Editor::Delete {
                            target,
                            id: id.clone(),
                            name: name.clone(),
                        });
                        cx.notify();
                    })),
            );
        }
        let confirming = matches!(
            editor,
            Editor::Delete { .. } | Editor::BulkDelete { .. } | Editor::ConfirmTool { .. }
        );
        let history = matches!(editor, Editor::History { .. });
        let save_label = match editor {
            Editor::Lifecycle(_) => "Run scenario",
            Editor::Faults(_) => "Arm faults",
            Editor::User { .. } => "Save user",
            Editor::Group { .. } => "Save group",
            Editor::Environment { .. } => "Save environment",
            Editor::Delete { .. } | Editor::BulkDelete { .. } => "Delete",
            Editor::History { .. } => "Close",
            Editor::RestoreBackup { .. } => "Restore backup",
            Editor::CreateUsers { .. } => "Create users",
            Editor::ConfirmTool { .. } => "Continue",
        };
        footer = footer
            .child(div().flex_1().min_w_0().whitespace_normal().when(
                matches!(editor, Editor::Faults(_) | Editor::Lifecycle(_)) && self.failed,
                |panel| {
                    panel.child(
                        super::view::accessible_status(
                            ("editor-error", self.status_revision),
                            self.message.clone(),
                            true,
                        )
                        .text_color(palette.danger)
                        .child(self.message.clone()),
                    )
                },
            ))
            .child(
                Button::new("cancel")
                    .label(if history { "Close" } else { "Cancel" })
                    .h(px(29.))
                    .ghost()
                    .disabled(self.busy)
                    .on_click(cx.listener(|view, _, _, cx| view.close_editor(cx))),
            )
            .when(!history, |footer| {
                footer.child(
                    Button::new("save")
                        .label(if self.busy { "Saving…" } else { save_label })
                        .h(px(29.))
                        .when(confirming, |button| button.danger())
                        .when(!confirming, |button| button.primary())
                        .disabled(self.busy)
                        .on_click(cx.listener(|view, _, _, cx| view.save(cx))),
                )
            });
        let subtitle = match editor {
            Editor::Environment {
                id: Some(_), name, ..
            } => name.read(cx).value().to_string(),
            Editor::Environment { .. } => "Create a directory for the app you are testing".into(),
            _ => self
                .directory()
                .map(|directory| directory.environment.name.clone())
                .unwrap_or_default(),
        };
        div()
            .id("editor-backdrop")
            .absolute()
            .inset_0()
            .flex()
            .items_center()
            .justify_center()
            .bg(rgba(0x00000040))
            .occlude()
            .on_click(cx.listener(|view, _, window, cx| {
                view.request_editor_dismiss(window, cx);
                cx.stop_propagation();
            }))
            .child(
                div()
                    .id("editor-sheet")
                    .role(gpui::Role::Dialog)
                    .a11y_synthetic_children({
                        let confirming = self.discard_return_focus.is_some();
                        move |builder| {
                            builder.parent_node().set_modal();
                            if confirming {
                                builder.parent_node().set_hidden();
                            }
                        }
                    })
                    .aria_label(title)
                    .aria_description(subtitle.clone())
                    .v_flex()
                    .w(px(640.))
                    .max_h_full()
                    .m_6()
                    .rounded_xl()
                    .overflow_hidden()
                    .border_1()
                    .border_color(palette.line)
                    .bg(palette.card)
                    .shadow_xl()
                    .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                    .on_mouse_up(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                    .child(
                        div()
                            .h_flex()
                            .px_5()
                            .py_3()
                            .gap_4()
                            .border_b_1()
                            .border_color(palette.line)
                            .bg(palette.soft)
                            .child(
                                div()
                                    .v_flex()
                                    .gap_1()
                                    .flex_1()
                                    .child(
                                        div().font_weight(gpui::FontWeight::SEMIBOLD).child(title),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(12.))
                                            .text_color(palette.muted)
                                            .child(subtitle),
                                    ),
                            )
                            .child(
                                Button::new("close-editor")
                                    .label("Close")
                                    .ghost()
                                    .h(px(29.))
                                    .disabled(self.busy)
                                    .on_click(cx.listener(|view, _, _, cx| view.close_editor(cx))),
                            ),
                    )
                    .child(
                        div()
                            .id("editor-content")
                            .min_h_0()
                            .overflow_y_scrollbar()
                            .child(body),
                    )
                    .child(footer)
                    .focus_trap("editor-focus", &self.editor_focus),
            )
            .when(self.discard_return_focus.is_some(), |overlay| {
                overlay.child(self.discard_confirmation(cx))
            })
            .into_any_element()
    }
}
