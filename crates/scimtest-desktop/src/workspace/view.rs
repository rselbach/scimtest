use crate::dropdown::DropdownMenu;
use gpui::{
    ClipboardItem, Context, Div, IntoElement, Render, SharedString, Window, div, img, prelude::*,
    px, rgb, svg,
};
use gpui_component::{
    Disableable, Icon, Selectable, StyledExt,
    button::{Button, ButtonVariants},
    menu::PopupMenuItem,
};

use super::{Tab, Workspace};
use crate::theme::Palette;

pub(super) fn icon(path: &'static str) -> Icon {
    Icon::default().path(path)
}

pub(super) fn cell(id: &'static str, text: impl Into<SharedString>) -> gpui::Stateful<Div> {
    let text = text.into();
    div()
        .id(id)
        .role(gpui::Role::Cell)
        .aria_label(text.clone())
        .flex_1()
        .min_w_0()
        .overflow_hidden()
        .text_ellipsis()
        .whitespace_nowrap()
        .child(text)
}

pub(super) fn accessible_text(
    id: impl Into<gpui::ElementId>,
    text: impl Into<SharedString>,
) -> gpui::Text {
    gpui::Text::new(id.into(), text.into())
}

pub(super) fn accessible_status(
    id: impl Into<gpui::ElementId>,
    text: String,
    failed: bool,
) -> gpui::Stateful<Div> {
    div()
        .id(id)
        .role(if failed {
            gpui::Role::Alert
        } else {
            gpui::Role::Status
        })
        .aria_label(text.clone())
        .a11y_synthetic_children(move |builder| {
            let node = builder.parent_node();
            node.set_value(text.clone());
            node.set_read_only();
            node.set_live(if text.is_empty() {
                gpui::accesskit::Live::Off
            } else if failed {
                gpui::accesskit::Live::Assertive
            } else {
                gpui::accesskit::Live::Polite
            });
        })
}

fn badge(count: usize, selected: bool, palette: Palette) -> Div {
    div()
        .px_2()
        .rounded_full()
        .text_size(px(11.))
        .text_color(if selected {
            palette.accent
        } else {
            palette.muted
        })
        .bg(if selected {
            palette.accent.opacity(0.12)
        } else {
            palette.muted.opacity(0.12)
        })
        .child(count.to_string())
}

impl Workspace {
    fn toolbar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = Palette::get(cx);
        let selected_name = self
            .directory()
            .map(|directory| directory.environment.name.as_str())
            .unwrap_or("No environments");
        let directories = self.directories.clone();
        let view = cx.weak_entity();
        div()
            .h_flex()
            .h(px(52.))
            .flex_shrink_0()
            .px_4()
            .gap_2()
            .border_b_1()
            .border_color(palette.line)
            .bg(palette.toolbar)
            .child(
                img(gpui::ImageSource::Resource(gpui::Resource::Embedded(
                    "app-icon.png".into(),
                )))
                .size(px(24.))
                .rounded_md(),
            )
            .child(
                div()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("scimtest"),
            )
            .child(div().flex_1())
            .when(self.updates.read(cx).available(), |toolbar| {
                toolbar.child(crate::updates::button(&self.updates, cx))
            })
            .child(
                Button::new("help-menu")
                    .label("Help")
                    .ghost()
                    .dropdown_menu(|menu, _, _| {
                        menu.item(PopupMenuItem::new("scimtest Help").on_click(|_, _, cx| {
                            crate::information::show_about(cx);
                        }))
                        .item(
                            PopupMenuItem::new("What's New in scimtest").on_click(|_, _, cx| {
                                crate::information::show_release_notes(cx);
                            }),
                        )
                        .item(
                            PopupMenuItem::new("Documentation").on_click(|_, _, cx| {
                                cx.open_url("https://github.com/rselbach/scimtest#readme");
                            }),
                        )
                    }),
            )
            .child(
                Button::new("account-settings")
                    .track_focus(&self.account_button_focus)
                    .label(if self.tunnel_snapshot.connected {
                        "Account & public URL"
                    } else {
                        "Account & connection"
                    })
                    .ghost()
                    .justify_start()
                    .on_click(cx.listener(|view, _, _, cx| {
                        view.account_open = true;
                        view.message.clear();
                        view.failed = false;
                        cx.notify();
                    })),
            )
            .child(
                div()
                    .text_size(px(11.))
                    .text_color(palette.muted)
                    .child("Active environment"),
            )
            .child(
                Button::new("environment-picker")
                    .label(selected_name.to_owned())
                    .icon(icon("icons/chevron-down.svg"))
                    .h(px(29.))
                    .w(px(190.))
                    .disabled(self.busy || directories.is_empty())
                    .dropdown_menu(move |mut menu, _, _| {
                        for directory in &directories {
                            let id = directory.environment.id.clone();
                            let view = view.clone();
                            menu = menu.item(
                                PopupMenuItem::new(directory.environment.name.clone()).on_click(
                                    move |_, _, cx| {
                                        let _ = view.update(cx, |view, cx| {
                                            view.selected = Some(id.clone());
                                            let enabled = view.directory().is_some_and(
                                                |directory| match view.tab {
                                                    Tab::Scim => {
                                                        directory.environment.settings.scim_enabled
                                                    }
                                                    Tab::Oidc => directory
                                                        .environment
                                                        .settings
                                                        .supports_oidc(),
                                                    Tab::Saml => directory
                                                        .environment
                                                        .settings
                                                        .supports_saml(),
                                                    Tab::Resilience => {
                                                        directory
                                                            .environment
                                                            .settings
                                                            .supports_oidc()
                                                            || directory
                                                                .environment
                                                                .settings
                                                                .supports_saml()
                                                    }
                                                    _ => true,
                                                },
                                            );
                                            if !enabled {
                                                view.tab = Tab::Users;
                                            }
                                            view.oidc = Default::default();
                                            view.saml = Default::default();
                                            view.scim_view = Default::default();
                                            view.resilience = Default::default();
                                            view.lifecycle = Default::default();
                                            if view.tab == Tab::Scim {
                                                view.refresh_scim(cx);
                                            }
                                            if matches!(
                                                view.tab,
                                                Tab::Oidc
                                                    | Tab::Saml
                                                    | Tab::Resilience
                                                    | Tab::Lifecycle
                                            ) {
                                                view.refresh_identity(cx);
                                            }
                                            view.selected_rows.clear();
                                            view.page = 0;
                                            view.status_filter = "All";
                                            view.table_scroll.set_offset(Default::default());
                                            view.editor = None;
                                            view.message.clear();
                                            cx.notify();
                                        });
                                    },
                                ),
                            );
                        }
                        menu
                    }),
            )
            .child(
                Button::new("manage-environments")
                    .label("Manage")
                    .link()
                    .h(px(29.))
                    .disabled(self.busy)
                    .on_click(cx.listener(|view, _, _, cx| {
                        view.tab = Tab::Environments;
                        view.table_scroll.set_offset(Default::default());
                        view.message.clear();
                        cx.notify();
                    })),
            )
            .child(
                div()
                    .ml_3()
                    .px_2()
                    .py_1()
                    .rounded_md()
                    .border_1()
                    .border_color(palette.line)
                    .text_size(px(11.))
                    .text_color(palette.muted)
                    .child("Rust preview"),
            )
    }

    fn navigation_item(
        &self,
        tab: Tab,
        label: &'static str,
        path: &'static str,
        count: usize,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let palette = Palette::get(cx);
        let selected = self.tab == tab;
        Button::new(label)
            .accessibility_label(label)
            .ghost()
            .w_full()
            .selected(selected)
            .toggled(selected)
            .disabled(self.busy)
            .h(px(30.))
            .px_2()
            .gap_2()
            .rounded_md()
            .when(selected, |row| row.bg(palette.selected))
            .child(svg().path(path).size(px(15.)).text_color(if selected {
                palette.accent
            } else {
                palette.muted
            }))
            .child(div().flex_1().text_left().child(label))
            .child(badge(count, selected, palette))
            .on_click(cx.listener(move |view, _, _, cx| {
                if view.busy {
                    return;
                }
                view.tab = tab;
                view.selected_rows.clear();
                view.page = 0;
                view.status_filter = "All";
                view.table_scroll.set_offset(Default::default());
                view.editor = None;
                view.message.clear();
                if tab == Tab::Scim {
                    view.refresh_scim(cx);
                }
                if matches!(
                    tab,
                    Tab::Oidc | Tab::Saml | Tab::Resilience | Tab::Lifecycle
                ) {
                    view.refresh_identity(cx);
                }
                if tab == Tab::Traffic {
                    view.refresh_traffic(cx);
                }
                cx.notify();
            }))
    }

    fn sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = Palette::get(cx);
        let directory = self.directory();
        let mut sidebar = div()
            .v_flex()
            .w(px(226.))
            .flex_shrink_0()
            .px_2()
            .py_4()
            .border_r_1()
            .border_color(palette.line)
            .bg(palette.sidebar);
        if let Some(directory) = directory {
            sidebar = sidebar
                .child(
                    div()
                        .px_2()
                        .py_2()
                        .text_size(px(11.))
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .text_color(palette.muted)
                        .child(directory.environment.name.clone()),
                )
                .child(self.navigation_item(
                    Tab::Users,
                    "Users",
                    "icons/user.svg",
                    directory.users.len(),
                    cx,
                ))
                .child(self.navigation_item(
                    Tab::Groups,
                    "Groups",
                    "icons/users.svg",
                    directory.groups.len(),
                    cx,
                ))
                .when(directory.environment.settings.supports_oidc(), |sidebar| {
                    sidebar.child(self.navigation_item(
                        Tab::Oidc,
                        "OIDC inspector",
                        "icons/environments.svg",
                        self.oidc.inspections.len(),
                        cx,
                    ))
                })
                .when(directory.environment.settings.supports_saml(), |sidebar| {
                    sidebar.child(self.navigation_item(
                        Tab::Saml,
                        "SAML inspector",
                        "icons/environments.svg",
                        self.saml.inspections.len(),
                        cx,
                    ))
                })
                .when(directory.environment.settings.scim_enabled, |sidebar| {
                    sidebar.child(self.navigation_item(
                        Tab::Scim,
                        "SCIM provisioning",
                        "icons/environments.svg",
                        scimtest_core::scim::plan(directory).len(),
                        cx,
                    ))
                })
                .when(
                    directory.environment.settings.supports_oidc()
                        || directory.environment.settings.supports_saml(),
                    |sidebar| {
                        sidebar.child(self.navigation_item(
                            Tab::Resilience,
                            "Fault injection",
                            "icons/environments.svg",
                            usize::from(self.resilience_active()),
                            cx,
                        ))
                    },
                )
                .child(self.navigation_item(
                    Tab::Lifecycle,
                    "Lifecycle",
                    "icons/environments.svg",
                    self.lifecycle.runs.len(),
                    cx,
                ))
                .child(
                    Button::new("environment-settings")
                        .label("Set up this environment")
                        .icon(icon("icons/environments.svg"))
                        .ghost()
                        .h(px(29.))
                        .justify_start()
                        .disabled(self.busy)
                        .on_click(cx.listener(|view, _, window, cx| {
                            let environment = view
                                .directory()
                                .map(|directory| directory.environment.clone());
                            view.edit_environment(environment.as_ref(), window, cx);
                        })),
                );
        }
        sidebar
            .child(
                div()
                    .mt_5()
                    .px_2()
                    .py_2()
                    .text_size(px(11.))
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .text_color(palette.muted)
                    .child("Global"),
            )
            .child(self.navigation_item(
                Tab::Environments,
                "Environments",
                "icons/environments.svg",
                self.directories.len(),
                cx,
            ))
            .child(self.navigation_item(
                Tab::Traffic,
                "Traffic",
                "icons/environments.svg",
                self.traffic.snapshot.entries.len(),
                cx,
            ))
            .child(div().flex_1())
            .child(
                div()
                    .p_2()
                    .text_size(px(11.))
                    .text_color(palette.muted)
                    .child("Directory preview"),
            )
    }

    fn page_header(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = Palette::get(cx);
        let (title, path, action, subtitle) = match self.tab {
            Tab::Lifecycle => (
                "Lifecycle",
                "icons/environments.svg",
                "New scenario…",
                "Run joiner, mover, and leaver workflows and inspect each step.".into(),
            ),
            Tab::Users => (
                "Users",
                "icons/user.svg",
                "+  Add user",
                self.directory()
                    .map(|directory| format!("Users in {}.", directory.environment.name))
                    .unwrap_or_else(|| "Create an environment before adding users.".into()),
            ),
            Tab::Groups => (
                "Groups",
                "icons/users.svg",
                "+  Add group",
                self.directory()
                    .map(|directory| format!("Groups in {}.", directory.environment.name))
                    .unwrap_or_else(|| "Create an environment before adding groups.".into()),
            ),
            Tab::Scim => (
                "SCIM provisioning",
                "icons/environments.svg",
                "Sync changes",
                "Provision directory changes, reconcile remote state, and inspect requests.".into(),
            ),
            Tab::Oidc => (
                "OIDC inspector",
                "icons/environments.svg",
                "Run sign-in",
                "Exercise sign-in, inspect claims, and manage tokens and sessions.".into(),
            ),
            Tab::Saml => (
                "SAML inspector",
                "icons/environments.svg",
                "Run sign-in",
                "Inspect assertions, exercise validation, and test single logout.".into(),
            ),
            Tab::Environments => (
                "Environments",
                "icons/environments.svg",
                "+  Add environment",
                "Each environment is one app you are testing.".into(),
            ),
            Tab::Resilience => (
                "Fault injection",
                "icons/environments.svg",
                "Disarm scenario",
                "Arm a scenario, then exercise sign-in or key discovery to inspect recovery."
                    .into(),
            ),
            Tab::Traffic => (
                "Traffic",
                "icons/environments.svg",
                "Clear traffic",
                "Capture identity exchanges and inspect requests, responses, and decoded payloads."
                    .into(),
            ),
        };
        div()
            .h_flex()
            .gap_4()
            .mb_6()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_center()
                    .size(px(44.))
                    .rounded_lg()
                    .bg(palette.accent)
                    .shadow_md()
                    .child(svg().path(path).size(px(22.)).text_color(rgb(0xffffff))),
            )
            .child(
                div()
                    .v_flex()
                    .flex_1()
                    .gap_1()
                    .child(
                        div()
                            .id("page-title")
                            .role(gpui::Role::Heading)
                            .aria_label(title)
                            .text_size(px(25.))
                            .font_weight(gpui::FontWeight::BOLD)
                            .text_color(palette.strong)
                            .child(title),
                    )
                    .child(div().text_color(palette.muted).child(subtitle)),
            )
            .child(
                Button::new("add-entry")
                    .label(action)
                    .h(px(29.))
                    .primary()
                    .disabled(
                        self.busy
                            || (self.tab == Tab::Scim && self.scim_running())
                            || (self.tab == Tab::Resilience && !self.resilience_active())
                            || (!matches!(self.tab, Tab::Environments | Tab::Traffic)
                                && self.selected.is_none()),
                    )
                    .on_click(cx.listener(|view, _, window, cx| match view.tab {
                        Tab::Users => view.edit_user(None, window, cx),
                        Tab::Groups => view.edit_group(None, window, cx),
                        Tab::Environments => view.edit_environment(None, window, cx),
                        Tab::Oidc => view.run_oidc(cx),
                        Tab::Saml => view.run_saml(cx),
                        Tab::Scim => view.scim_action("sync", None, cx),
                        Tab::Traffic => view.traffic_action("clear", cx),
                        Tab::Resilience => view.disarm_resilience(cx),
                        Tab::Lifecycle => view.edit_lifecycle("joiner", window, cx),
                    })),
            )
    }
}

impl Workspace {
    fn content(&mut self, cx: &mut Context<Self>) -> Div {
        if self.account_locked() || self.account_open {
            return div().size_full().child(self.account_screen(cx));
        }
        let palette = Palette::get(cx);
        let footer = if self.message.is_empty() {
            self.directory()
                .map(|directory| directory.environment.name.clone())
                .unwrap_or_else(|| "No active environment".into())
        } else {
            self.message.clone()
        };
        let background = div()
            .id("workspace-background")
            .role(gpui::Role::Group)
            .a11y_synthetic_children({
                let modal = self.editor.is_some();
                move |builder| {
                    if modal {
                        builder.parent_node().set_hidden();
                    }
                }
            })
            .v_flex()
            .size_full()
            .bg(palette.canvas)
            .child(self.toolbar(cx))
            .child(
                div()
                    .flex()
                    .flex_row()
                    .flex_1()
                    .min_h_0()
                    .child(self.sidebar(cx))
                    .child(
                        div()
                            .v_flex()
                            .flex_1()
                            .min_w_0()
                            .min_h_0()
                            .px(px(50.))
                            .pt(px(30.))
                            .pb_6()
                            .child(self.page_header(cx))
                            .child(self.table(cx)),
                    ),
            )
            .child(
                div()
                    .h_flex()
                    .h(px(34.))
                    .flex_shrink_0()
                    .px_5()
                    .gap_5()
                    .border_t_1()
                    .border_color(palette.line)
                    .bg(palette.toolbar)
                    .child(
                        div()
                            .text_size(px(11.))
                            .text_color(palette.success)
                            .child("scimtest"),
                    )
                    .child(
                        accessible_status(
                            ("workspace-status", self.status_revision),
                            self.message.clone(),
                            self.failed && !self.message.is_empty(),
                        )
                        .aria_label(footer.clone())
                        .text_size(px(11.))
                        .flex_1()
                        .text_color(if self.failed {
                            palette.danger
                        } else {
                            palette.muted
                        })
                        .child(footer),
                    )
                    .child(
                        Button::new("copy-api")
                            .label("Copy local API URL")
                            .h(px(29.))
                            .ghost()
                            .on_click(cx.listener(|view, _, _, cx| {
                                cx.write_to_clipboard(ClipboardItem::new_string(
                                    view.api_url.clone(),
                                ));
                                view.message = "Local API URL copied".into();
                                view.failed = false;
                                cx.notify();
                            })),
                    ),
            );
        div()
            .relative()
            .size_full()
            .text_size(px(13.))
            .text_color(palette.text)
            .on_key_down(cx.listener(|view, event: &gpui::KeyDownEvent, window, cx| {
                if event.keystroke.key == "escape" && view.editor.is_some() {
                    view.request_editor_dismiss(window, cx);
                    cx.stop_propagation();
                }
            }))
            .child(background)
            .when(self.editor.is_some(), |root| root.child(self.editor(cx)))
    }
}

impl Render for Workspace {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.update_focus(window, cx);
        if window.focused(cx).is_none() {
            window.focus(&self.focus, cx);
        }
        let content = self.content(cx);
        div()
            .id("workspace")
            .role(gpui::Role::Group)
            .aria_label("scimtest workspace")
            .size_full()
            .key_context("Workspace")
            .track_focus(&self.focus)
            .child(content)
    }
}
