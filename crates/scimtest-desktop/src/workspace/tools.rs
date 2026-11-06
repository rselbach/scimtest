use crate::dropdown::DropdownMenu;
use gpui::{Context, IntoElement, prelude::*, px};
use gpui_component::{Disableable, button::Button, menu::PopupMenuItem};

use super::{Editor, Workspace, input};

impl Workspace {
    pub(super) fn tools_menu(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.weak_entity();
        Button::new("directory-tools")
            .label("Tools")
            .h(px(29.))
            .disabled(self.busy || self.selected.is_none())
            .dropdown_menu(move |mut menu, _, _| {
                for (label, action) in [
                    ("Create users…", "create-users"),
                    ("Activate all users", "activate-all"),
                    ("Deactivate all users", "deactivate-all"),
                    ("Delete all users…", "delete-all"),
                    ("Clear local directory…", "clear-local"),
                    ("Save backup…", "backup"),
                    ("Restore backup…", "restore"),
                ] {
                    let view = view.clone();
                    menu = menu.item(PopupMenuItem::new(label).on_click(move |_, window, cx| {
                        let _ = view.update(cx, |view, cx| {
                            match action {
                                "backup" => view.export_backup(cx),
                                "restore" => view.import_backup(cx),
                                "create-users" => {
                                    view.editor = Some(Editor::CreateUsers {
                                        count: input("10", "Number of users", window, cx),
                                        domain: input("greendale.edu", "Email domain", window, cx),
                                    });
                                }
                                "delete-all" | "clear-local" => {
                                    view.editor = Some(Editor::ConfirmTool { action });
                                }
                                _ => {
                                    let environment = view.selected.clone().unwrap_or_default();
                                    view.command(
                                        move |store| {
                                            let result = store.set_all_active(
                                                &environment,
                                                action == "activate-all",
                                            )?;
                                            Ok((
                                                format!("Changed {} users", result.users_changed),
                                                None,
                                            ))
                                        },
                                        cx,
                                    );
                                }
                            }
                            cx.notify();
                        });
                    }));
                }
                menu
            })
    }
}
