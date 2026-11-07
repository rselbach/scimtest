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

const SORT_OPTIONS: [&str; 2] = ["Name A–Z", "Name Z–A"];
const PAGE_SIZES: [usize; 4] = [15, 25, 50, 100];

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
        if self.sort_descending {
            users.reverse();
        }
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
        if self.sort_descending {
            groups.reverse();
        }
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
            .border_b_1()
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
                        .w(px(110.))
                        .child("Active"),
                )
                .child(
                    div()
                        .id("actions")
                        .role(gpui::Role::ColumnHeader)
                        .aria_label("Actions")
                        .w(px(110.))
                        .text_right()
                        .child("Actions"),
                ),
            Tab::Groups => heading
                .child(cell("name", "Group").role(gpui::Role::ColumnHeader))
                .child(
                    div()
                        .id("members")
                        .role(gpui::Role::ColumnHeader)
                        .aria_label("Members")
                        .w(px(160.))
                        .child("Members"),
                )
                .child(
                    div()
                        .id("actions")
                        .role(gpui::Role::ColumnHeader)
                        .aria_label("Actions")
                        .w(px(110.))
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
                .child(cell("name", "Environment").role(gpui::Role::ColumnHeader))
                .child(cell("protocol", "Protocol").role(gpui::Role::ColumnHeader))
                .child(
                    div()
                        .id("actions")
                        .role(gpui::Role::ColumnHeader)
                        .aria_label("Actions")
                        .w(px(150.))
                        .text_right()
                        .child("Actions"),
                ),
        };
        let mut rows = div().v_flex().flex_shrink_0();
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
                            "Add your own entries or load the Greendale sample from Bulk tools."
                        },
                    ))),
            );
        }
        let mut table = div()
            .v_flex()
            .min_h_0()
            .max_h_full()
            .rounded_lg()
            .border_1()
            .border_color(palette.line)
            .bg(palette.card)
            .overflow_hidden()
            .shadow_sm();
        if self.tab != Tab::Environments {
            table = table.child(self.selection_bar(noun, cx));
        }
        table = table.child(
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
        );
        if self.tab != Tab::Environments {
            table = table.child(self.table_footer(count, start, end, page, last_page, cx));
        }
        table
    }

    fn selection_bar(&self, noun: &'static str, cx: &mut Context<Self>) -> gpui::Div {
        let palette = Palette::get(cx);
        let selected = self.selected_rows.len();
        div()
            .h_flex()
            .h(px(46.))
            .flex_shrink_0()
            .px_4()
            .gap_3()
            .justify_end()
            .items_center()
            .border_b_1()
            .border_color(palette.line)
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(palette.muted)
                    .child(format!(
                        "{selected} {noun}{} selected",
                        if selected == 1 { "" } else { "s" }
                    )),
            )
            .child(
                Button::new("delete-selected")
                    .label("Delete selected")
                    .h(px(29.))
                    .outline()
                    .danger()
                    .disabled(self.busy || self.selected_rows.is_empty())
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
            )
    }

    fn table_footer(
        &self,
        count: usize,
        start: usize,
        end: usize,
        page: usize,
        last_page: usize,
        cx: &mut Context<Self>,
    ) -> gpui::Div {
        let palette = Palette::get(cx);
        let view = cx.weak_entity();
        let range = if count == 0 {
            "Showing 0 of 0".to_owned()
        } else {
            format!("Showing {}–{} of {count}", start + 1, end)
        };
        let status_label = if self.status_filter == "All" {
            "All statuses"
        } else {
            self.status_filter
        };
        let filters = if self.tab == Tab::Users {
            vec![
                "All", "Active", "Inactive", "Pending", "Synced", "Error", "Deleted",
            ]
        } else {
            vec!["All", "Pending", "Synced", "Error", "Deleted"]
        };
        let filter_view = view.clone();
        let sort_view = view.clone();
        let size_view = view.clone();
        div()
            .h_flex()
            .h(px(46.))
            .flex_shrink_0()
            .px_4()
            .gap_4()
            .justify_between()
            .items_center()
            .border_t_1()
            .border_color(palette.line)
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(palette.muted)
                    .child(range),
            )
            .child(
                div()
                    .h_flex()
                    .gap_2()
                    .items_center()
                    .child(footer_label("Search", palette))
                    .child(
                        div().w(px(181.)).child(
                            Input::new(&self.search)
                                .aria_label("Search directory")
                                .accessibility_id("directory-search"),
                        ),
                    )
                    .child(footer_label("Status", palette))
                    .child(
                        Button::new("status-filter")
                            .accessibility_label(format!("Status filter: {status_label}"))
                            .label(status_label)
                            .h(px(29.))
                            .dropdown_menu(move |mut menu, _, _| {
                                for filter in &filters {
                                    let filter = *filter;
                                    let view = filter_view.clone();
                                    let label = if filter == "All" {
                                        "All statuses"
                                    } else {
                                        filter
                                    };
                                    menu = menu.item(PopupMenuItem::new(label).on_click(
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
                    )
                    .child(footer_label("Sort", palette))
                    .child(
                        Button::new("sort-order")
                            .accessibility_label(format!(
                                "Sort: {}",
                                sort_label(self.sort_descending)
                            ))
                            .label(sort_label(self.sort_descending))
                            .h(px(29.))
                            .dropdown_menu(move |mut menu, _, _| {
                                for (index, option) in SORT_OPTIONS.iter().enumerate() {
                                    let view = sort_view.clone();
                                    menu = menu.item(PopupMenuItem::new(*option).on_click(
                                        move |_, _, cx| {
                                            let _ = view.update(cx, |view, cx| {
                                                view.sort_descending = index == 1;
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
                    .child(footer_label("Rows", palette))
                    .child(
                        Button::new("page-size")
                            .label(self.page_size.to_string())
                            .h(px(29.))
                            .dropdown_menu(move |mut menu, _, _| {
                                for size in PAGE_SIZES {
                                    let view = size_view.clone();
                                    menu =
                                        menu.item(PopupMenuItem::new(size.to_string()).on_click(
                                            move |_, _, cx| {
                                                let _ = view.update(cx, |view, cx| {
                                                    view.page_size = size;
                                                    view.page = 0;
                                                    view.table_scroll
                                                        .set_offset(Default::default());
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
                            .h(px(29.))
                            .ghost()
                            .disabled(page == 0)
                            .on_click(cx.listener(move |view, _, _, cx| {
                                view.page = page.saturating_sub(1);
                                view.table_scroll.set_offset(Default::default());
                                cx.notify();
                            })),
                    )
                    .child(
                        Button::new("next-page")
                            .label("Next")
                            .h(px(29.))
                            .ghost()
                            .disabled(page >= last_page)
                            .on_click(cx.listener(move |view, _, _, cx| {
                                view.page = page + 1;
                                view.table_scroll.set_offset(Default::default());
                                cx.notify();
                            })),
                    ),
            )
    }
}

fn footer_label(label: &'static str, palette: Palette) -> gpui::Div {
    div()
        .text_size(px(12.))
        .text_color(palette.muted)
        .child(label)
}

fn sort_label(descending: bool) -> &'static str {
    SORT_OPTIONS[usize::from(descending)]
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
