use rune::{El, ScrollSpec, Tx, col, el, row};
use rune_kit::{Button, ButtonVariant, Checkbox, TextInput};
use scimtest_core::model::{Directory, Group, User};

use super::{
    DeleteTarget, Editor, Tab, Workspace,
    view::{Choice, caption, dropdown, font_text, rule},
};
use crate::theme::{SEMIBOLD, Ui};

const SORT_OPTIONS: [&str; 2] = ["Name A–Z", "Name Z–A"];
const PAGE_SIZES: [usize; 4] = [15, 25, 50, 100];

/// A table cell that takes an equal share of the row.
pub(super) fn cell(key: &'static str, value: impl Into<String>, ui: &Ui) -> El {
    let value = value.into();
    font_text(value.clone(), 13.0, 400.0, ui.p.text, ui)
        .key(key)
        .role("cell")
        .label(value)
        .grow(1.0)
        .min_w(0.0)
        .truncate()
}

fn header(key: &'static str, label: &'static str, width: Option<f32>, ui: &Ui) -> El {
    let header = font_text(label, 11.0, 400.0, ui.p.muted, ui)
        .key(key)
        .role("columnheader")
        .label(label);
    match width {
        Some(width) => header.w(width),
        None => header.grow(1.0).min_w(0.0),
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

impl Workspace {
    /// The users matching the search and status filter, in the chosen order.
    pub(super) fn visible_users(&self) -> Vec<User> {
        let query = self.search.text.to_lowercase();
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
        users
    }

    /// The groups matching the search and status filter, in the chosen order.
    pub(super) fn visible_groups(&self) -> Vec<Group> {
        let query = self.search.text.to_lowercase();
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
        groups
    }

    pub(super) fn table(&self, ui: &Ui, layer: &mut Vec<El>) -> El {
        let p = ui.p;
        let users = self.visible_users();
        let groups = self.visible_groups();
        let (count, noun) = match self.tab {
            Tab::Users => (users.len(), "user"),
            Tab::Groups => (groups.len(), "group"),
            _ => (self.directories.len(), "environment"),
        };
        let paged = self.tab != Tab::Environments;
        let last_page = count.saturating_sub(1) / self.page_size;
        let page = self.page.min(last_page);
        let start = if paged { page * self.page_size } else { 0 };
        let end = if paged {
            (start + self.page_size).min(count)
        } else {
            count
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
            _ => Vec::new(),
        };
        let mut heading = row()
            .key("table-heading")
            .role("row")
            .w_full()
            .h(34.0)
            .px(16.0)
            .gap(16.0)
            .center_y()
            .fill(p.soft);
        if paged {
            let checked = !ids.is_empty() && ids.iter().all(|id| self.selected_rows.contains(id));
            heading = heading.child(
                el().w(20.0).child(
                    Checkbox::new(checked)
                        .label("Select all on this page")
                        .hide_label()
                        .disabled(self.busy || ids.is_empty())
                        .on_toggle(move |s: &mut Workspace| {
                            for id in &ids {
                                if checked {
                                    s.selected_rows.remove(id);
                                } else {
                                    s.selected_rows.insert(id.clone());
                                }
                            }
                        })
                        .build(&ui.k)
                        .key("select-page"),
                ),
            );
        }
        heading = match self.tab {
            Tab::Users => heading
                .child(header("name", "Name", None, ui))
                .child(header("username", "Username", None, ui))
                .child(header("email", "Email", None, ui))
                .child(header("active", "Active", Some(110.0), ui))
                .child(header("actions", "Actions", Some(110.0), ui).align(rune::Align::End)),
            Tab::Groups => heading
                .child(header("name", "Group", None, ui))
                .child(header("members", "Members", Some(160.0), ui))
                .child(header("actions", "Actions", Some(110.0), ui).align(rune::Align::End)),
            _ => heading
                .child(header("name", "Environment", None, ui))
                .child(header("protocol", "Protocol", None, ui))
                .child(header("actions", "Actions", Some(150.0), ui).align(rune::Align::End)),
        };
        let mut rows = col().key("directory-rows").w_full();
        rows = match self.tab {
            Tab::Users => {
                rows.children(users[start..end].iter().map(|user| self.user_row(user, ui)))
            }
            Tab::Groups => rows.children(
                groups[start..end]
                    .iter()
                    .map(|group| self.group_row(group, ui)),
            ),
            _ => rows.children(
                self.directories
                    .iter()
                    .map(|directory| self.environment_row(directory, ui)),
            ),
        };
        if count == 0 {
            let query = !self.search.text.is_empty() || self.status_filter != "All";
            rows = rows.child(
                col()
                    .key("empty")
                    .w_full()
                    .padding(40.0)
                    .gap(8.0)
                    .center()
                    .child(
                        font_text(format!("No {noun}s found"), 13.0, SEMIBOLD, p.text, ui)
                            .key("empty-title"),
                    )
                    .child(
                        font_text(
                            if self.tab == Tab::Environments {
                                "Add an environment to get started."
                            } else if query {
                                "Try a different search or status."
                            } else {
                                "Add your own entries or load the Greendale sample from Bulk tools."
                            },
                            13.0,
                            400.0,
                            p.muted,
                            ui,
                        )
                        .key("empty-description"),
                    ),
            );
        }
        let mut table = col()
            .key("directory")
            .w_full()
            .min_h(0.0)
            .radius(11.0)
            .border(1.0, p.line)
            .fill(p.card)
            .clip_rounded(11.0)
            .shadow(1.0, 3.0, rune::Color::BLACK.alpha(0.06));
        if paged {
            table = table.child(self.selection_bar(noun, ui)).child(rule(p));
        }
        table = table.child(
            col()
                .key("directory-table")
                .role("table")
                .label(format!("{noun}s"))
                .w_full()
                .min_h(0.0)
                .shrink()
                .child(heading)
                .child(rule(p))
                .child(
                    col()
                        .key("directory-scroll")
                        .w_full()
                        .min_h(0.0)
                        .shrink()
                        .scroll(ScrollSpec {
                            stick_bottom: false,
                        })
                        .child(rows),
                ),
        );
        if paged {
            table = table
                .child(rule(p))
                .child(self.table_footer(count, start, end, page, last_page, ui, layer));
        }
        table
    }

    fn selection_bar(&self, noun: &'static str, ui: &Ui) -> El {
        let selected = self.selected_rows.len();
        row()
            .key("selection-bar")
            .w_full()
            .h(46.0)
            .px(16.0)
            .gap(12.0)
            .justify_end()
            .center_y()
            .child(
                font_text(
                    format!(
                        "{selected} {noun}{} selected",
                        if selected == 1 { "" } else { "s" }
                    ),
                    12.0,
                    400.0,
                    ui.p.muted,
                    ui,
                )
                .key("selection-count"),
            )
            .child(
                Button::new("Delete selected")
                    .variant(ButtonVariant::Danger)
                    .disabled(self.busy || self.selected_rows.is_empty())
                    .on_press(|s: &mut Workspace| {
                        let target = if s.tab == Tab::Users {
                            DeleteTarget::User
                        } else {
                            DeleteTarget::Group
                        };
                        let ids = s.selected_rows.iter().cloned().collect();
                        s.open_editor(Editor::BulkDelete { target, ids });
                    })
                    .build(&ui.k)
                    .key("delete-selected"),
            )
    }

    #[allow(clippy::too_many_arguments)]
    fn table_footer(
        &self,
        count: usize,
        start: usize,
        end: usize,
        page: usize,
        last_page: usize,
        ui: &Ui,
        layer: &mut Vec<El>,
    ) -> El {
        let k = &ui.k;
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
        let filters: &[&'static str] = if self.tab == Tab::Users {
            &[
                "All", "Active", "Inactive", "Pending", "Synced", "Error", "Deleted",
            ]
        } else {
            &["All", "Pending", "Synced", "Error", "Deleted"]
        };
        let filter_choices = filters
            .iter()
            .map(|&filter| {
                Choice::new(
                    if filter == "All" {
                        "All statuses"
                    } else {
                        filter
                    },
                    move |s: &mut Workspace| {
                        s.status_filter = filter;
                        s.page = 0;
                    },
                )
                .checked(self.status_filter == filter)
            })
            .collect();
        let sort_choices = SORT_OPTIONS
            .iter()
            .enumerate()
            .map(|(index, option)| {
                Choice::new(*option, move |s: &mut Workspace| {
                    s.sort_descending = index == 1;
                    s.page = 0;
                })
                .checked(usize::from(self.sort_descending) == index)
            })
            .collect();
        let size_choices = PAGE_SIZES
            .iter()
            .map(|&size| {
                Choice::new(size.to_string(), move |s: &mut Workspace| {
                    s.page_size = size;
                    s.page = 0;
                })
                .checked(self.page_size == size)
            })
            .collect();
        let sort_label = SORT_OPTIONS[usize::from(self.sort_descending)];
        row()
            .key("table-footer")
            .w_full()
            .h(46.0)
            .px(16.0)
            .gap(16.0)
            .justify_between()
            .center_y()
            .child(font_text(range, 12.0, 400.0, ui.p.muted, ui).key("table-range"))
            .child(
                row()
                    .gap(8.0)
                    .center_y()
                    .child(caption("Search", ui))
                    .child(
                        TextInput::new(&self.search)
                            .label("Search directory")
                            .placeholder("name, username, email")
                            .width(Some(181.0))
                            .on_edit(|s: &mut Workspace| &mut s.search)
                            .on_change(|s: &mut Workspace, _: &mut Tx| s.page = 0)
                            .build(k)
                            .key("directory-search"),
                    )
                    .child(caption("Status", ui))
                    .child(
                        dropdown(
                            self,
                            "status-filter",
                            status_label,
                            None,
                            false,
                            filter_choices,
                            ui,
                            layer,
                        )
                        .label(format!("Status filter: {status_label}")),
                    )
                    .child(caption("Sort", ui))
                    .child(
                        dropdown(
                            self,
                            "sort-order",
                            sort_label,
                            None,
                            false,
                            sort_choices,
                            ui,
                            layer,
                        )
                        .label(format!("Sort: {sort_label}")),
                    )
                    .child(caption("Rows", ui))
                    .child(
                        dropdown(
                            self,
                            "page-size",
                            self.page_size.to_string(),
                            None,
                            false,
                            size_choices,
                            ui,
                            layer,
                        )
                        .label(format!("Rows per page: {}", self.page_size)),
                    )
                    .child(
                        Button::new("Previous")
                            .variant(ButtonVariant::Ghost)
                            .disabled(page == 0)
                            .on_press(move |s: &mut Workspace| s.page = page.saturating_sub(1))
                            .build(k)
                            .key("previous-page"),
                    )
                    .child(
                        Button::new("Next")
                            .variant(ButtonVariant::Ghost)
                            .disabled(page >= last_page)
                            .on_press(move |s: &mut Workspace| s.page = page + 1)
                            .build(k)
                            .key("next-page"),
                    ),
            )
    }
}
