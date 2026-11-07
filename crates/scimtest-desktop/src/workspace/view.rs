use crate::dropdown::DropdownMenu;
use gpui::{
    Context, Div, IntoElement, Render, SharedString, Window, div, img, prelude::*, px, rgb, svg,
};
use gpui_component::{
    Disableable, Icon, Selectable, StyledExt,
    button::{Button, ButtonVariants},
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

/// Small pill for a status such as "Recording" or "Healthy".
pub(super) fn status_pill(label: impl Into<SharedString>, color: gpui::Hsla) -> Div {
    div()
        .h_flex()
        .gap_1p5()
        .px_2p5()
        .py_1()
        .rounded_full()
        .bg(color.opacity(0.14))
        .text_size(px(11.))
        .text_color(color)
        .child(div().size(px(6.)).rounded_full().bg(color))
        .child(label.into())
}

/// A sidebar button that is not a page tab, laid out like a navigation item.
fn sidebar_action(
    id: &'static str,
    label: &'static str,
    path: &'static str,
    palette: Palette,
) -> Button {
    Button::new(id)
        .accessibility_label(label)
        .ghost()
        .w_full()
        .h(px(30.))
        .px_2()
        .gap_2()
        .rounded_md()
        .child(svg().path(path).size(px(15.)).text_color(palette.muted))
        .child(div().flex_1().text_left().child(label))
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
        let signed_in =
            self.tunnel_snapshot.connected && !self.tunnel_snapshot.github_login.is_empty();
        let mut toolbar = div()
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
            .child(div().flex_1());
        if self.updates.read(cx).available() {
            toolbar = toolbar.child(crate::updates::button(&self.updates, cx));
        }
        toolbar = toolbar
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
                                gpui_component::menu::PopupMenuItem::new(
                                    directory.environment.name.clone(),
                                )
                                .on_click(move |_, _, cx| {
                                    let _ = view.update(cx, |view, cx| {
                                        view.select_environment(id.clone(), cx);
                                    });
                                }),
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
            .child(div().flex_1());
        let account_label = if signed_in {
            format!("Signed in as @{}", self.tunnel_snapshot.github_login)
        } else {
            "Account & connection".to_owned()
        };
        toolbar = toolbar.child(
            Button::new("account-settings")
                .track_focus(&self.account_button_focus)
                .label(account_label)
                .ghost()
                .h(px(29.))
                .on_click(cx.listener(|view, _, _, cx| {
                    view.account_open = true;
                    view.message.clear();
                    view.failed = false;
                    cx.notify();
                })),
        );
        if signed_in {
            toolbar = toolbar.child(
                Button::new("sign-out")
                    .label("Log out")
                    .outline()
                    .h(px(29.))
                    .disabled(self.busy || self.account_busy)
                    .on_click(cx.listener(|view, _, _, cx| view.sign_out_account(cx))),
            );
        }
        toolbar
    }

    fn navigation_item(
        &self,
        tab: Tab,
        label: &'static str,
        path: &'static str,
        count: Option<usize>,
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
            .when_some(count, |row, count| {
                row.child(badge(count, selected, palette))
            })
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
                    Some(directory.users.len()),
                    cx,
                ))
                .child(self.navigation_item(
                    Tab::Groups,
                    "Groups",
                    "icons/users.svg",
                    Some(directory.groups.len()),
                    cx,
                ))
                .when(directory.environment.settings.supports_oidc(), |sidebar| {
                    sidebar.child(self.navigation_item(
                        Tab::Oidc,
                        "OIDC Inspector",
                        "icons/id-card.svg",
                        None,
                        cx,
                    ))
                })
                .when(directory.environment.settings.supports_saml(), |sidebar| {
                    sidebar.child(self.navigation_item(
                        Tab::Saml,
                        "SAML Inspector",
                        "icons/id-card.svg",
                        None,
                        cx,
                    ))
                })
                .when(directory.environment.settings.scim_enabled, |sidebar| {
                    sidebar.child(self.navigation_item(
                        Tab::Scim,
                        "SCIM provisioning",
                        "icons/environments.svg",
                        None,
                        cx,
                    ))
                })
                .when(
                    directory.environment.settings.supports_oidc()
                        || directory.environment.settings.supports_saml(),
                    |sidebar| {
                        sidebar.child(self.navigation_item(
                            Tab::Resilience,
                            "Fault Injection",
                            "icons/shield.svg",
                            None,
                            cx,
                        ))
                    },
                )
                .child(self.navigation_item(
                    Tab::Lifecycle,
                    "Lifecycle",
                    "icons/lifecycle.svg",
                    None,
                    cx,
                ))
                .child(
                    sidebar_action(
                        "environment-settings",
                        "Set up this environment",
                        "icons/environments.svg",
                        palette,
                    )
                    .disabled(self.busy)
                    .on_click(cx.listener(|view, _, window, cx| {
                        let environment = view
                            .directory()
                            .map(|directory| directory.environment.clone());
                        view.edit_environment(environment.as_ref(), window, cx);
                    })),
                )
                .child(
                    sidebar_action("bulk-tools", "Bulk tools", "icons/tools.svg", palette)
                        .disabled(self.busy)
                        .on_click(cx.listener(|view, _, window, cx| {
                            view.open_tools(window, cx);
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
                Some(self.directories.len()),
                cx,
            ))
            .child(
                sidebar_action("idp-tunnel", "IDP & tunnel", "icons/globe.svg", palette)
                    .disabled(self.busy)
                    .on_click(cx.listener(|view, _, window, cx| {
                        view.open_idp(window, cx);
                    })),
            )
            .child(self.navigation_item(Tab::Traffic, "Traffic", "icons/pulse.svg", None, cx))
            .child(div().flex_1())
    }

    fn page_header(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = Palette::get(cx);
        let environment = self
            .directory()
            .map(|directory| directory.environment.name.clone())
            .unwrap_or_default();
        let (title, path, subtitle): (&str, &'static str, String) = match self.tab {
            Tab::Lifecycle => (
                "Lifecycle",
                "icons/lifecycle.svg",
                format!(
                    "Run joiner, mover, and leaver scenarios against {environment} and see what it did with each message."
                ),
            ),
            Tab::Users => (
                "Users",
                "icons/user.svg",
                self.directory()
                    .map(|directory| format!("Users in {}.", directory.environment.name))
                    .unwrap_or_else(|| "Create an environment before adding users.".into()),
            ),
            Tab::Groups => (
                "Groups",
                "icons/users.svg",
                self.directory()
                    .map(|directory| format!("Groups in {}.", directory.environment.name))
                    .unwrap_or_else(|| "Create an environment before adding groups.".into()),
            ),
            Tab::Scim => (
                "SCIM provisioning",
                "icons/environments.svg",
                "Provision directory changes, reconcile remote state, and inspect requests.".into(),
            ),
            Tab::Oidc => (
                "OIDC Inspector",
                "icons/id-card.svg",
                format!("Authorization, token, and userinfo activity for {environment}."),
            ),
            Tab::Saml => (
                "SAML Inspector",
                "icons/id-card.svg",
                "Inspect assertions, exercise validation, and test single logout.".into(),
            ),
            Tab::Environments => (
                "Environments",
                "icons/environments.svg",
                "Each environment is one app you are testing. Use Test sign-in to run a flow, Inspect flow to debug it, or Set up to find connection values.".into(),
            ),
            Tab::Resilience => (
                "Fault Injection",
                "icons/shield.svg",
                format!("Test how {environment} handles identity infrastructure failures."),
            ),
            Tab::Traffic => (
                "Traffic",
                "icons/pulse.svg",
                "Live OIDC and SAML request and response transcripts for debugging sign-in flows."
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
            .child(self.header_actions(cx))
    }

    fn header_actions(&self, cx: &mut Context<Self>) -> Div {
        let palette = Palette::get(cx);
        let no_environment = self.selected.is_none();
        match self.tab {
            Tab::Users => div().child(
                Button::new("add-entry")
                    .label("+ Add user")
                    .h(px(29.))
                    .primary()
                    .disabled(self.busy || no_environment)
                    .on_click(cx.listener(|view, _, window, cx| view.edit_user(None, window, cx))),
            ),
            Tab::Groups => div().child(
                Button::new("add-entry")
                    .label("+ Add group")
                    .h(px(29.))
                    .primary()
                    .disabled(self.busy || no_environment)
                    .on_click(cx.listener(|view, _, window, cx| view.edit_group(None, window, cx))),
            ),
            Tab::Environments => div().child(
                Button::new("add-entry")
                    .label("+ Add environment")
                    .h(px(29.))
                    .primary()
                    .disabled(self.busy)
                    .on_click(
                        cx.listener(|view, _, window, cx| view.edit_environment(None, window, cx)),
                    ),
            ),
            Tab::Oidc => div()
                .h_flex()
                .gap_2()
                .child(
                    Button::new("run-oidc")
                        .label("Test with built-in RP")
                        .h(px(29.))
                        .primary()
                        .disabled(self.busy || no_environment)
                        .on_click(cx.listener(|view, _, _, cx| view.run_oidc(cx))),
                )
                .child(
                    Button::new("open-faults")
                        .label("Fault Injection")
                        .h(px(29.))
                        .outline()
                        .disabled(self.busy || no_environment)
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.tab = Tab::Resilience;
                            view.refresh_identity(cx);
                            cx.notify();
                        })),
                ),
            Tab::Saml => div().child(
                Button::new("add-entry")
                    .label("Run sign-in")
                    .h(px(29.))
                    .primary()
                    .disabled(self.busy || no_environment)
                    .on_click(cx.listener(|view, _, _, cx| view.run_saml(cx))),
            ),
            Tab::Scim => div().child(
                Button::new("add-entry")
                    .label("Sync changes")
                    .h(px(29.))
                    .primary()
                    .disabled(self.busy || self.scim_running() || no_environment)
                    .on_click(cx.listener(|view, _, _, cx| view.scim_action("sync", None, cx))),
            ),
            Tab::Resilience => {
                let active = self.resilience_active();
                div()
                    .h_flex()
                    .gap_2()
                    .when(active, |row| {
                        row.child(
                            Button::new("add-entry")
                                .label("Disarm scenario")
                                .h(px(29.))
                                .outline()
                                .disabled(self.busy)
                                .on_click(cx.listener(|view, _, _, cx| view.disarm_resilience(cx))),
                        )
                    })
                    .child(if active {
                        status_pill("Scenario armed", palette.accent)
                    } else {
                        status_pill("Healthy", palette.success)
                    })
            }
            Tab::Traffic => {
                if self.traffic.snapshot.record {
                    div().child(status_pill("Recording", palette.success))
                } else {
                    div().child(status_pill("Not recording", palette.muted))
                }
            }
            Tab::Lifecycle => div(),
        }
    }
}

impl Workspace {
    fn content(&mut self, cx: &mut Context<Self>) -> Div {
        if self.account_locked() || self.account_open {
            return div().size_full().child(self.account_screen(cx));
        }
        let palette = Palette::get(cx);
        let idp_base = self
            .tunnel_snapshot
            .public_url
            .clone()
            .unwrap_or_else(|| self.api_url.clone());
        let status = self.directory().map(|directory| {
            format!(
                "{} SCIM: {}",
                directory.environment.name,
                if directory.environment.settings.scim_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            )
        });
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
                            .h_flex()
                            .gap_1p5()
                            .text_size(px(11.))
                            .text_color(palette.muted)
                            .child(div().size(px(6.)).rounded_full().bg(palette.success))
                            .child("scimtest"),
                    )
                    .child(
                        accessible_status(
                            ("workspace-status", self.status_revision),
                            self.message.clone(),
                            self.failed && !self.message.is_empty(),
                        )
                        .text_size(px(11.))
                        .flex_1()
                        .text_color(if self.failed {
                            palette.danger
                        } else {
                            palette.muted
                        })
                        .child(self.message.clone()),
                    )
                    .when_some(status, |bar, status| {
                        bar.child(
                            div()
                                .text_size(px(11.))
                                .text_color(palette.muted)
                                .child(status),
                        )
                    })
                    .child(
                        div()
                            .text_size(px(11.))
                            .text_color(palette.muted)
                            .child(format!("IDP base: {idp_base}")),
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
