use std::collections::BTreeSet;

use crate::dropdown::DropdownMenu;
use gpui::{
    Context, Div, Entity, IntoElement, MouseButton, SharedString, div, prelude::*, px, rgba, svg,
};
use gpui_component::{
    Disableable, FocusTrapElement, StyledExt,
    button::{Button, ButtonVariants},
    checkbox::Checkbox,
    input::{Input, InputState, Textarea, TextareaState},
    menu::PopupMenuItem,
    scroll::ScrollableElement,
};
use scimtest_core::model::OperationLog;

use super::{
    DeleteTarget, Editor, Workspace,
    view::{accessible_status, accessible_text, icon},
};
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

/// A field whose label row carries a muted hint on the right.
fn field_with_hint(
    label: &'static str,
    hint: &'static str,
    state: &Entity<InputState>,
    cx: &Context<Workspace>,
) -> impl IntoElement {
    let palette = Palette::get(cx);
    div()
        .v_flex()
        .flex_1()
        .min_w_0()
        .gap_2()
        .child(
            div()
                .h_flex()
                .justify_between()
                .child(div().text_size(px(12.)).child(label))
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(palette.muted)
                        .child(hint),
                ),
        )
        .child(Input::new(state).aria_label(label))
}

fn two_columns(left: impl IntoElement, right: impl IntoElement) -> Div {
    div()
        .h_flex()
        .items_start()
        .gap_4()
        .child(left)
        .child(right)
}

impl Workspace {
    pub(super) fn editor(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = Palette::get(cx);
        let Some(editor) = &self.editor else {
            return div().into_any_element();
        };
        let title: SharedString = match editor {
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
            Editor::History { noun: "", name, .. } => name.clone().into(),
            Editor::History { noun, name, .. } => format!("{noun} History: {name}").into(),
            Editor::RestoreBackup { .. } => "Restore environment backup".into(),
            Editor::Tools { .. } => "Bulk tools".into(),
            Editor::Idp { .. } => "IDP and tunnel settings".into(),
            Editor::ConfirmTool {
                action: "clear-local",
            } => "Clear local directory".into(),
            Editor::ConfirmTool { .. } => "Delete all users".into(),
        };
        let subtitle: SharedString = match editor {
            Editor::Environment { .. } => {
                "The authentication and provisioning context used while testing".into()
            }
            Editor::History { .. } => "Newest first".into(),
            Editor::Tools { .. } => "Create or update many test users at once.".into(),
            Editor::Idp { .. } => "".into(),
            _ => self
                .directory()
                .map(|directory| directory.environment.name.clone())
                .unwrap_or_default()
                .into(),
        };
        let width = match editor {
            Editor::Environment { .. } | Editor::Group { .. } => 880.,
            Editor::History { .. } => 960.,
            _ => 640.,
        };
        let mut body = div().v_flex().gap_5().p_5();
        match editor {
            Editor::Lifecycle(form) => body = body.child(form.fields(self, cx)),
            Editor::Faults(form) => body = body.child(form.fields(self.busy, cx)),
            Editor::Environment {
                id,
                name,
                slug,
                settings,
            } => {
                body = body.child(settings.body(self, name, slug, id.as_deref(), cx));
            }
            Editor::User {
                id,
                fields,
                active,
                manager,
                attributes,
                ..
            } => {
                body = body.child(self.user_form(
                    id.as_deref(),
                    fields,
                    *active,
                    manager,
                    attributes,
                    cx,
                ));
            }
            Editor::Group {
                id: _,
                name,
                search,
                members,
            } => {
                body = body.child(self.group_form(name, search, members, cx));
            }
            Editor::Delete { target, name, .. } => {
                body = body
                    .child(
                        div()
                            .font_weight(gpui::FontWeight::MEDIUM)
                            .child(accessible_text(
                                "delete-question",
                                format!("Delete {name}?"),
                            )),
                    )
                    .child(div().text_color(palette.muted).child(accessible_text(
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
                    )));
            }
            Editor::Tools { count, domain } => {
                body = body.child(self.tools_body(count, domain, cx));
            }
            Editor::Idp {
                base_url,
                trust_proxy,
            } => {
                body = body.child(self.idp_body(base_url, *trust_proxy, cx));
            }
            Editor::ConfirmTool { action } => {
                body = body.child(div().child(accessible_text(
                    "tool-question",
                    if *action == "clear-local" {
                        "Remove all local users, groups, sync state, and operation history? Remote resources stay in place."
                    } else {
                        "Delete every user in this environment? Users tracked by SCIM remain available to restore until their remote deletion completes."
                    },
                )));
            }
            Editor::RestoreBackup { backup } => {
                body = body
                    .child(div().child(accessible_text(
                        "restore-question",
                        format!(
                            "Restore the backup from {}? It contains {} user{} and {} group{}.",
                            backup.exported_at,
                            backup.state.users.len(),
                            if backup.state.users.len() == 1 { "" } else { "s" },
                            backup.state.groups.len(),
                            if backup.state.groups.len() == 1 { "" } else { "s" },
                        ),
                    )))
                    .child(div().text_color(palette.muted).child(accessible_text(
                        "restore-detail",
                        "This replaces the selected environment. A safety copy of the current state will be saved first.",
                    )));
            }
            Editor::BulkDelete { ids, .. } => {
                body = body
                    .child(div().child(accessible_text(
                        "delete-question",
                        format!(
                            "Delete {} selected {}?",
                            ids.len(),
                            if ids.len() == 1 { "entry" } else { "entries" }
                        ),
                    )))
                    .child(div().text_color(palette.muted).child(accessible_text(
                        "delete-detail",
                        if self
                            .directory()
                            .is_some_and(|directory| directory.tracks_scim())
                        {
                            "Entries remain available to restore until their remote deletion completes."
                        } else {
                            "This removes the selected entries from this directory."
                        },
                    )));
            }
            Editor::History {
                entries, expanded, ..
            } => {
                body = body.child(self.history_entries(entries, expanded, cx));
            }
        }
        if self.failed
            && !self.message.is_empty()
            && !matches!(editor, Editor::Faults(_) | Editor::Lifecycle(_))
        {
            body = body.child(
                accessible_status(
                    ("editor-error", self.status_revision),
                    self.message.clone(),
                    true,
                )
                .text_color(palette.danger)
                .child(self.message.clone()),
            );
        }
        let footer = self.editor_footer(editor, cx);
        let subtitle_text = subtitle.clone();
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
                    .aria_label(title.clone())
                    .aria_description(subtitle_text.clone())
                    .v_flex()
                    .w(px(width))
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
                            .child(
                                div()
                                    .v_flex()
                                    .gap_1()
                                    .flex_1()
                                    .child(
                                        div()
                                            .text_size(px(15.))
                                            .font_weight(gpui::FontWeight::SEMIBOLD)
                                            .child(title),
                                    )
                                    .when(!subtitle.is_empty(), |header| {
                                        header.child(
                                            div()
                                                .text_size(px(12.))
                                                .text_color(palette.muted)
                                                .child(subtitle),
                                        )
                                    }),
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
                    .children(footer)
                    .focus_trap("editor-focus", &self.editor_focus),
            )
            .when(self.discard_return_focus.is_some(), |overlay| {
                overlay.child(self.discard_confirmation(cx))
            })
            .into_any_element()
    }

    /// Footer actions for the open editor. Returns `None` for read-only panels.
    fn editor_footer(&self, editor: &Editor, cx: &mut Context<Self>) -> Option<Div> {
        let palette = Palette::get(cx);
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
        let save = Button::new("save")
            .label(if self.busy {
                "Saving…".to_owned()
            } else {
                save_label.to_owned()
            })
            .h(px(29.))
            .when(confirming, |button| button.danger())
            .when(!confirming, |button| button.primary())
            .disabled(self.busy)
            .on_click(cx.listener(|view, _, _, cx| view.save(cx)));
        let cancel = Button::new("cancel")
            .label("Cancel")
            .h(px(29.))
            .ghost()
            .disabled(self.busy)
            .on_click(cx.listener(|view, _, _, cx| view.close_editor(cx)));
        let mut footer = div()
            .h_flex()
            .gap_2()
            .px_5()
            .py_4()
            .border_t_1()
            .border_color(palette.line)
            .items_center();
        match editor {
            Editor::Environment { settings, .. } => {
                footer = footer
                    .child(cancel)
                    .child(div().flex_1())
                    .child(settings.nav(cx))
                    .child(save);
            }
            Editor::Idp { .. } => {
                footer = footer
                    .child(
                        Button::new("copy-api")
                            .label("Copy local API URL")
                            .h(px(29.))
                            .ghost()
                            .on_click(cx.listener(|view, _, _, cx| {
                                cx.write_to_clipboard(gpui::ClipboardItem::new_string(
                                    view.api_url.clone(),
                                ));
                                view.message = "Local API URL copied".into();
                                view.failed = false;
                                cx.notify();
                            })),
                    )
                    .child(div().flex_1())
                    .child(cancel)
                    .child(save);
            }
            Editor::User { id: Some(id), .. } if self.scim_enabled() => {
                let id = id.clone();
                footer = footer
                    .child(
                        Button::new("push-user")
                            .label("Push to SCIM")
                            .h(px(29.))
                            .ghost()
                            .disabled(self.busy)
                            .on_click(cx.listener(move |view, _, _, cx| {
                                view.editor = None;
                                view.scim_action("push", Some(("user".into(), id.clone())), cx);
                            })),
                    )
                    .child(div().flex_1())
                    .child(cancel)
                    .child(save);
            }
            _ => {
                footer = footer.child(div().flex_1()).child(cancel).child(save);
            }
        }
        if matches!(editor, Editor::Faults(_) | Editor::Lifecycle(_)) && self.failed {
            footer = footer.child(
                accessible_status(
                    ("editor-error", self.status_revision),
                    self.message.clone(),
                    true,
                )
                .text_color(palette.danger)
                .child(self.message.clone()),
            );
        }
        Some(footer)
    }

    fn scim_enabled(&self) -> bool {
        self.directory()
            .is_some_and(|directory| directory.environment.settings.scim_enabled)
    }

    /// A disclosure header that expands or collapses the section it names.
    pub(super) fn disclosure(
        &self,
        key: &'static str,
        label: &'static str,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let palette = Palette::get(cx);
        let open = self.disclosures.contains(key);
        div()
            .id(key)
            .role(gpui::Role::Button)
            .aria_label(label)
            .h_flex()
            .gap_1p5()
            .items_center()
            .cursor_pointer()
            .text_size(px(12.))
            .font_weight(gpui::FontWeight::SEMIBOLD)
            .text_color(palette.accent)
            .child(
                svg()
                    .path(if open {
                        "icons/chevron-down.svg"
                    } else {
                        "icons/chevron-right.svg"
                    })
                    .size(px(12.))
                    .text_color(palette.accent),
            )
            .child(label)
            .on_click(cx.listener(move |view, _, _, cx| {
                if !view.disclosures.remove(key) {
                    view.disclosures.insert(key);
                }
                cx.notify();
            }))
    }

    fn user_form(
        &self,
        id: Option<&str>,
        fields: &[Entity<InputState>; 9],
        active: bool,
        manager: &str,
        attributes: &Entity<TextareaState>,
        cx: &mut Context<Self>,
    ) -> Div {
        let palette = Palette::get(cx);
        let mut form = div()
            .v_flex()
            .gap_3()
            .child(two_columns(
                field_with_hint("Username", "Uses email when left blank", &fields[3], cx),
                field_with_hint("Email", "", &fields[2], cx),
            ))
            .child(two_columns(
                field_with_hint("Given name", "", &fields[0], cx),
                field_with_hint("Family name", "Optional", &fields[1], cx),
            ))
            .child(
                Checkbox::new("user-active")
                    .label("Active")
                    .checked(active)
                    .disabled(self.busy)
                    .on_click(cx.listener(|view, checked: &bool, _, cx| {
                        if let Some(Editor::User { active, .. }) = &mut view.editor {
                            *active = *checked;
                            view.editor_dirty = true;
                        }
                        cx.notify();
                    })),
            )
            .child(self.disclosure("user-enterprise", "Enterprise attributes", cx));
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
            let view = cx.weak_entity();
            form = form.child(
                div()
                    .v_flex()
                    .gap_4()
                    .pl_3()
                    .child(two_columns(
                        field_with_hint("Employee number", "", &fields[4], cx),
                        field_with_hint("Cost center", "", &fields[5], cx),
                    ))
                    .child(two_columns(
                        field_with_hint("Organization", "", &fields[6], cx),
                        field_with_hint("Division", "", &fields[7], cx),
                    ))
                    .child(two_columns(
                        field_with_hint("Department", "", &fields[8], cx),
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
                                    .icon(icon("icons/chevron-down.svg"))
                                    .justify_between()
                                    .border_1()
                                    .border_color(palette.line)
                                    .rounded_md()
                                    .disabled(self.busy)
                                    .dropdown_menu(move |mut menu, _, _| {
                                        for (id, name) in
                                            std::iter::once((String::new(), "No manager".into()))
                                                .chain(candidates.clone())
                                        {
                                            let view = view.clone();
                                            menu = menu.item(PopupMenuItem::new(name).on_click(
                                                move |_, _, cx| {
                                                    let _ = view.update(cx, |view, cx| {
                                                        if let Some(Editor::User {
                                                            manager, ..
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
                    )),
            );
        }
        form = form.child(self.disclosure("user-custom", "Custom attributes", cx));
        if self.disclosures.contains("user-custom") {
            form = form.child(
                div()
                    .v_flex()
                    .gap_2()
                    .pl_3()
                    .child(
                        div()
                            .text_size(px(11.))
                            .text_color(palette.muted)
                            .child("One name=value per line."),
                    )
                    .child(
                        Textarea::new(attributes)
                            .aria_label("Custom attributes (one name=value per line)"),
                    ),
            );
        }
        form
    }

    fn group_form(
        &self,
        name: &Entity<InputState>,
        search: &Entity<InputState>,
        members: &[String],
        cx: &mut Context<Self>,
    ) -> Div {
        let palette = Palette::get(cx);
        let query = search.read(cx).value().to_lowercase();
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
        // Each member is a direct child of the scroll container so the list
        // tracks scroll position per row.
        let mut grid = div()
            .id("member-scroll")
            .h_flex()
            .flex_wrap()
            .content_start()
            .max_h(px(300.))
            .border_1()
            .border_color(palette.line)
            .rounded_md()
            .bg(palette.soft)
            .overflow_y_scroll()
            .track_scroll(&self.member_scroll)
            .vertical_scrollbar(&self.member_scroll);
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
                div().w(gpui::relative(0.5)).p_1().child(
                    div()
                        .id(SharedString::from(format!("member-row-{id}")))
                        .h_flex()
                        .gap_3()
                        .items_center()
                        .p_3()
                        .rounded_md()
                        .border_1()
                        .border_color(palette.line)
                        .bg(palette.card)
                        .child(
                            Checkbox::new(SharedString::from(format!("member-{id}")))
                                .accessibility_label(name_text.clone())
                                .checked(checked)
                                .disabled(self.busy)
                                .on_click(cx.listener(move |view, checked: &bool, _, cx| {
                                    if let Some(Editor::Group { members, .. }) = &mut view.editor {
                                        members.retain(|member| member != &id);
                                        if *checked {
                                            members.push(id.clone());
                                        }
                                        view.editor_dirty = true;
                                    }
                                    cx.notify();
                                })),
                        )
                        .child(
                            div()
                                .v_flex()
                                .min_w_0()
                                .child(
                                    div()
                                        .font_weight(gpui::FontWeight::SEMIBOLD)
                                        .child(name_text),
                                )
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(palette.muted)
                                        .child(detail),
                                ),
                        ),
                ),
            );
        }
        if total == 0 {
            grid = grid.child(
                div()
                    .w_full()
                    .p_3()
                    .text_color(palette.muted)
                    .child("Add users to this environment first."),
            );
        }
        div()
            .v_flex()
            .gap_4()
            .child(field("Group name", name))
            .child(
                div()
                    .v_flex()
                    .gap_2()
                    .child(div().text_size(px(12.)).child("Members"))
                    .child(
                        div()
                            .h_flex()
                            .gap_3()
                            .items_center()
                            .child(
                                div()
                                    .flex_1()
                                    .child(Input::new(search).aria_label("Search users")),
                            )
                            .child(div().text_size(px(12.)).text_color(palette.muted).child(
                                format!(
                                    "Showing {} of {total} · {} selected",
                                    matching.len(),
                                    members.len()
                                ),
                            )),
                    )
                    .child(gpui_base::ScrollBounce::new(
                        "member-bounce",
                        &self.member_scroll,
                        grid,
                    )),
            )
    }

    fn history_entries(
        &self,
        entries: &[OperationLog],
        expanded: &BTreeSet<usize>,
        cx: &mut Context<Self>,
    ) -> Div {
        let palette = Palette::get(cx);
        let mut list = div().v_flex().gap_3();
        if entries.is_empty() {
            list = list.child(
                div()
                    .text_color(palette.muted)
                    .child("No operations recorded yet."),
            );
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
            let mut card = div()
                .id(("history-entry", index))
                .role(gpui::Role::Group)
                .aria_label(format!("{}: {}", entry.created_at, entry.summary))
                .v_flex()
                .gap_2()
                .p_3()
                .rounded_md()
                .border_1()
                .border_color(palette.line)
                .child(
                    div()
                        .h_flex()
                        .gap_2()
                        .items_center()
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(palette.muted)
                                .child(entry.created_at.clone()),
                        )
                        .child(
                            div()
                                .px_1p5()
                                .py_0p5()
                                .rounded_sm()
                                .border_1()
                                .border_color(palette.line)
                                .text_size(px(10.))
                                .text_color(palette.muted)
                                .child(entry.kind.to_uppercase()),
                        ),
                )
                .child(div().child(accessible_text(
                    ("history-summary", index),
                    entry.summary.clone(),
                )));
            if !details.is_empty() {
                card = card.child(
                    div()
                        .id(("history-toggle", index))
                        .role(gpui::Role::Button)
                        .aria_label("Show request and response")
                        .h_flex()
                        .gap_1p5()
                        .items_center()
                        .cursor_pointer()
                        .text_size(px(12.))
                        .text_color(palette.accent)
                        .child(
                            svg()
                                .path(if open {
                                    "icons/chevron-down.svg"
                                } else {
                                    "icons/chevron-right.svg"
                                })
                                .size(px(12.))
                                .text_color(palette.accent),
                        )
                        .child(if open {
                            "Hide request and response"
                        } else {
                            "Show request and response"
                        })
                        .on_click(cx.listener(move |view, _, _, cx| {
                            if let Some(Editor::History { expanded, .. }) = &mut view.editor
                                && !expanded.remove(&index)
                            {
                                expanded.insert(index);
                            }
                            cx.notify();
                        })),
                );
                if open {
                    for (value_index, value) in details.into_iter().enumerate() {
                        card = card.child(
                            div()
                                .p_2()
                                .rounded_md()
                                .bg(palette.soft)
                                .text_size(px(12.))
                                .whitespace_normal()
                                .child(accessible_text(("history-value", value_index), value)),
                        );
                    }
                }
            }
            list = list.child(card);
        }
        list
    }
}
