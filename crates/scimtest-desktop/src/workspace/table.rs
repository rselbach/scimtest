use super::{
    DeleteTarget, Editor, Tab, Workspace,
    view::{accessible_text, cell},
};
use crate::dropdown::DropdownMenu;
use crate::theme::Palette;
use gpui::{Context, div, prelude::*, px};
use gpui_component::{
    Disableable, StyledExt,
    button::{Button, ButtonVariants},
    checkbox::Checkbox,
    input::Input,
    menu::PopupMenuItem,
    scroll::ScrollableElement,
};
use scimtest_core::model::Directory;

impl Workspace {
    pub(super) fn table(&self, cx: &mut Context<Self>) -> gpui::Div {
        if self.tab == Tab::Lifecycle {
            return self.lifecycle_inspector(cx);
        }
        if self.tab == Tab::Resilience {
            return self.resilience_inspector(cx);
        }
        if self.tab == Tab::Traffic {
            return self.traffic_inspector(cx);
        }
        if self.tab == Tab::Scim {
            return self.scim_inspector(cx);
        }
        if self.tab == Tab::Oidc {
            return self.oidc_inspector(cx);
        }
        if self.tab == Tab::Saml {
            return self.saml_inspector(cx);
        }
        let palette = Palette::get(cx);
        let query = self.search.read(cx).value().to_lowercase();
        let mut users = self
            .directory()
            .map(Directory::projected_users)
            .unwrap_or_default();
        users.retain(|user| {
            let text = format!(
                "{} {} {} {} {} {}",
                user.fields.given_name,
                user.fields.family_name,
                user.fields.email,
                user.fields.username,
                user.fields.department,
                user.fields.organization
            )
            .to_lowercase();
            text.contains(&query)
                && match self.status_filter {
                    "Active" => user.fields.active && !user.deleted,
                    "Inactive" => !user.fields.active && !user.deleted,
                    value => matches_filter(
                        value,
                        user.deleted,
                        user.dirty,
                        &user.last_error,
                        &user.remote_id,
                    ),
                }
        });
        users.sort_by_key(|user| {
            format!("{} {}", user.fields.given_name, user.fields.family_name).to_lowercase()
        });
        let mut groups = self
            .directory()
            .map(Directory::projected_groups)
            .unwrap_or_default();
        groups.retain(|group| {
            group.fields.display_name.to_lowercase().contains(&query)
                && matches_filter(
                    self.status_filter,
                    group.deleted,
                    group.dirty,
                    &group.last_error,
                    &group.remote_id,
                )
        });
        groups.sort_by_key(|group| group.fields.display_name.to_lowercase());
        let count = match self.tab {
            Tab::Users => users.len(),
            Tab::Groups => groups.len(),
            Tab::Environments
            | Tab::Oidc
            | Tab::Saml
            | Tab::Scim
            | Tab::Traffic
            | Tab::Resilience
            | Tab::Lifecycle => self.directories.len(),
        };
        let noun = match self.tab {
            Tab::Users => "user",
            Tab::Groups => "group",
            Tab::Environments
            | Tab::Oidc
            | Tab::Saml
            | Tab::Scim
            | Tab::Traffic
            | Tab::Resilience
            | Tab::Lifecycle => "environment",
        };
        let last_page = count.saturating_sub(1) / self.page_size;
        let page = self.page.min(last_page);
        let start = if self.tab == Tab::Environments {
            0
        } else {
            page * self.page_size
        };
        let end = if self.tab == Tab::Environments {
            count
        } else {
            (start + self.page_size).min(count)
        };
        let ids = match self.tab {
            Tab::Users => users[start..end]
                .iter()
                .filter(|user| !user.deleted)
                .map(|user| user.id.clone())
                .collect::<Vec<_>>(),
            Tab::Groups => groups[start..end]
                .iter()
                .filter(|group| !group.deleted)
                .map(|group| group.id.clone())
                .collect(),
            Tab::Environments
            | Tab::Oidc
            | Tab::Saml
            | Tab::Scim
            | Tab::Traffic
            | Tab::Resilience
            | Tab::Lifecycle => vec![],
        };
        let mut heading = div()
            .id("table-heading")
            .role(gpui::Role::Row)
            .h_flex()
            .h(px(34.))
            .flex_shrink_0()
            .px_4()
            .gap_4()
            .border_y_1()
            .border_color(palette.line)
            .bg(palette.soft)
            .text_size(px(11.))
            .text_color(palette.muted);
        if self.tab != Tab::Environments {
            let checked = !ids.is_empty() && ids.iter().all(|id| self.selected_rows.contains(id));
            heading = heading.child(
                div().w(px(20.)).flex_shrink_0().child(
                    Checkbox::new("select-page")
                        .accessibility_label("Select all on this page")
                        .checked(checked)
                        .disabled(self.busy || ids.is_empty())
                        .on_click(cx.listener(move |view, checked: &bool, _, cx| {
                            for id in &ids {
                                if *checked {
                                    view.selected_rows.insert(id.clone());
                                } else {
                                    view.selected_rows.remove(id);
                                }
                            }
                            cx.notify();
                        })),
                ),
            );
        }
        heading = match self.tab {
            Tab::Users => heading
                .child(cell("name", "Name").role(gpui::Role::ColumnHeader))
                .child(cell("username", "Username").role(gpui::Role::ColumnHeader))
                .child(cell("email", "Email").role(gpui::Role::ColumnHeader))
                .child(
                    div()
                        .id("active")
                        .role(gpui::Role::ColumnHeader)
                        .aria_label("Active")
                        .w(px(98.))
                        .child("Active"),
                )
                .child(
                    div()
                        .id("sync")
                        .role(gpui::Role::ColumnHeader)
                        .aria_label("Sync")
                        .w(px(78.))
                        .child("Sync"),
                )
                .child(
                    div()
                        .id("actions")
                        .role(gpui::Role::ColumnHeader)
                        .aria_label("Actions")
                        .w(px(96.))
                        .text_right()
                        .child("Actions"),
                ),
            Tab::Groups => heading
                .child(cell("name", "Group").role(gpui::Role::ColumnHeader))
                .child(cell("members", "Members").role(gpui::Role::ColumnHeader))
                .child(
                    div()
                        .id("sync")
                        .role(gpui::Role::ColumnHeader)
                        .aria_label("Sync")
                        .w(px(78.))
                        .child("Sync"),
                )
                .child(
                    div()
                        .id("actions")
                        .role(gpui::Role::ColumnHeader)
                        .aria_label("Actions")
                        .w(px(96.))
                        .text_right()
                        .child("Actions"),
                ),
            Tab::Environments
            | Tab::Oidc
            | Tab::Saml
            | Tab::Scim
            | Tab::Traffic
            | Tab::Resilience
            | Tab::Lifecycle => heading
                .child(cell("name", "Name").role(gpui::Role::ColumnHeader))
                .child(cell("endpoint", "Endpoint name").role(gpui::Role::ColumnHeader))
                .child(
                    div()
                        .id("users")
                        .role(gpui::Role::ColumnHeader)
                        .aria_label("Users")
                        .w(px(65.))
                        .child("Users"),
                )
                .child(
                    div()
                        .id("groups")
                        .role(gpui::Role::ColumnHeader)
                        .aria_label("Groups")
                        .w(px(65.))
                        .child("Groups"),
                )
                .child(
                    div()
                        .id("actions")
                        .role(gpui::Role::ColumnHeader)
                        .aria_label("Actions")
                        .w(px(62.))
                        .child("Actions"),
                ),
        };
        let height = if self.tab == Tab::Environments {
            59.
        } else {
            51.
        };
        let mut rows = div()
            .v_flex()
            .flex_shrink_0()
            .when(count > 0, |rows| rows.h(px((end - start) as f32 * height)));
        rows = match self.tab {
            Tab::Users => {
                rows.children(users[start..end].iter().map(|user| self.user_row(user, cx)))
            }
            Tab::Groups => rows.children(
                groups[start..end]
                    .iter()
                    .map(|group| self.group_row(group, cx)),
            ),
            Tab::Environments
            | Tab::Oidc
            | Tab::Saml
            | Tab::Scim
            | Tab::Traffic
            | Tab::Resilience
            | Tab::Lifecycle => rows.children(
                self.directories
                    .iter()
                    .map(|directory| self.environment_row(directory, cx)),
            ),
        };
        if count == 0 {
            rows = rows.child(
                div()
                    .v_flex()
                    .items_center()
                    .justify_center()
                    .p_10()
                    .gap_2()
                    .child(
                        div()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(accessible_text("empty-title", format!("No {noun}s found"))),
                    )
                    .child(div().text_color(palette.muted).child(accessible_text(
                        "empty-description",
                        if self.tab == Tab::Environments {
                            "Add an environment to get started."
                        } else if !query.is_empty() || self.status_filter != "All" {
                            "Try a different search or status."
                        } else {
                            "Add your own entries or load the Greendale sample."
                        },
                    ))),
            );
        }
        let mut controls = div()
            .h_flex()
            .min_h(px(46.))
            .flex_shrink_0()
            .px_4()
            .py_2()
            .gap_2();
        if self.tab != Tab::Environments {
            let view = cx.weak_entity();
            let filters = if self.tab == Tab::Users {
                vec![
                    "All", "Active", "Inactive", "Pending", "Synced", "Error", "Deleted",
                ]
            } else {
                vec!["All", "Pending", "Synced", "Error", "Deleted"]
            };
            controls = controls
                .child(
                    div().w(px(200.)).child(
                        Input::new(&self.search)
                            .aria_label("Search directory")
                            .accessibility_id("directory-search"),
                    ),
                )
                .child(
                    Button::new("status-filter")
                        .accessibility_label(format!("Status filter: {}", self.status_filter))
                        .label(self.status_filter)
                        .h(px(29.))
                        .dropdown_menu(move |mut menu, _, _| {
                            for filter in &filters {
                                let filter = *filter;
                                let view = view.clone();
                                menu = menu.item(PopupMenuItem::new(filter).on_click(
                                    move |_, _, cx| {
                                        let _ = view.update(cx, |view, cx| {
                                            view.status_filter = filter;
                                            view.page = 0;
                                            view.table_scroll.set_offset(Default::default());
                                            cx.notify();
                                        });
                                    },
                                ));
                            }
                            menu
                        }),
                );
            if !self.selected_rows.is_empty() {
                controls = controls.child(
                    Button::new("delete-selected")
                        .label(format!("Delete ({})", self.selected_rows.len()))
                        .h(px(29.))
                        .ghost()
                        .disabled(self.busy)
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.editor = Some(Editor::BulkDelete {
                                target: if view.tab == Tab::Users {
                                    DeleteTarget::User
                                } else {
                                    DeleteTarget::Group
                                },
                                ids: view.selected_rows.iter().cloned().collect(),
                            });
                            cx.notify();
                        })),
                );
            }
        }
        controls = controls.child(div().flex_1());
        if self.tab != Tab::Environments {
            controls = controls.child(self.tools_menu(cx));
        }
        if self.tab != Tab::Environments
            && let Some(environment) = self.selected.clone()
        {
            controls = controls.child(
                Button::new("seed")
                    .label("Load Greendale sample")
                    .h(px(29.))
                    .disabled(self.busy)
                    .on_click(cx.listener(move |view, _, _, cx| {
                        let environment = environment.clone();
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
            );
        }
        let mut footer = div()
            .h_flex()
            .h(px(42.))
            .flex_shrink_0()
            .px_4()
            .gap_2()
            .border_t_1()
            .border_color(palette.line)
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(palette.muted)
                    .child(format!(
                        "{count} {noun}{}",
                        if count == 1 { "" } else { "s" }
                    )),
            )
            .child(div().flex_1());
        if self.tab != Tab::Environments {
            let view = cx.weak_entity();
            footer = footer
                .child(
                    Button::new("page-size")
                        .label(format!("{} per page", self.page_size))
                        .h(px(26.))
                        .ghost()
                        .dropdown_menu(move |mut menu, _, _| {
                            for size in [15, 25, 50, 100] {
                                let view = view.clone();
                                menu = menu.item(PopupMenuItem::new(size.to_string()).on_click(
                                    move |_, _, cx| {
                                        let _ = view.update(cx, |view, cx| {
                                            view.page_size = size;
                                            view.page = 0;
                                            view.table_scroll.set_offset(Default::default());
                                            cx.notify();
                                        });
                                    },
                                ));
                            }
                            menu
                        }),
                )
                .child(
                    Button::new("previous-page")
                        .label("Previous")
                        .h(px(26.))
                        .ghost()
                        .disabled(page == 0)
                        .on_click(cx.listener(move |view, _, _, cx| {
                            view.page = page.saturating_sub(1);
                            view.table_scroll.set_offset(Default::default());
                            cx.notify();
                        })),
                )
                .child(
                    div()
                        .text_size(px(12.))
                        .child(format!("{} / {}", page + 1, last_page + 1)),
                )
                .child(
                    Button::new("next-page")
                        .label("Next")
                        .h(px(26.))
                        .ghost()
                        .disabled(page >= last_page)
                        .on_click(cx.listener(move |view, _, _, cx| {
                            view.page = page + 1;
                            view.table_scroll.set_offset(Default::default());
                            cx.notify();
                        })),
                );
        }
        div()
            .v_flex()
            .min_h_0()
            .max_h_full()
            .rounded_lg()
            .border_1()
            .border_color(palette.line)
            .bg(palette.card)
            .overflow_hidden()
            .shadow_sm()
            .child(controls)
            .child(
                div()
                    .id("directory-table")
                    .role(gpui::Role::Table)
                    .aria_label(format!("{noun}s"))
                    .v_flex()
                    .min_h_0()
                    .child(heading)
                    .child(
                        div()
                            .id("directory-scroll")
                            .relative()
                            .min_h_0()
                            .overflow_y_scroll()
                            .track_scroll(&self.table_scroll)
                            .child(rows)
                            .vertical_scrollbar(&self.table_scroll),
                    ),
            )
            .child(footer)
    }
}

fn matches_filter(filter: &str, deleted: bool, dirty: bool, error: &str, remote: &str) -> bool {
    match filter {
        "Deleted" => deleted,
        "Error" => !error.is_empty(),
        "Pending" => dirty && !deleted,
        "Synced" => !deleted && !dirty && error.is_empty() && !remote.is_empty(),
        _ => true,
    }
}
