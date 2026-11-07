use rune::{Color, Cx, El, Icon, LiveRegion, Tx, col, el, icon, row, text};
use rune_kit::{Button, ButtonVariant, Menu, MenuItem};

use super::{Tab, Workspace};
use crate::{
    icons,
    theme::{BOLD, Palette, SEMIBOLD, Ui},
};

/// One choice in a dropdown menu.
pub(crate) struct Choice {
    label: String,
    checked: bool,
    action: Box<dyn Fn(&mut Workspace)>,
}

impl Choice {
    pub(crate) fn new(label: impl Into<String>, action: impl Fn(&mut Workspace) + 'static) -> Self {
        Self {
            label: label.into(),
            checked: false,
            action: Box::new(action),
        }
    }

    pub(crate) fn checked(mut self, checked: bool) -> Self {
        self.checked = checked;
        self
    }
}

/// A button that opens a menu of `choices`; picking one closes the menu and runs it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn dropdown(
    s: &Workspace,
    key: &str,
    label: impl Into<String>,
    width: Option<f32>,
    disabled: bool,
    choices: Vec<Choice>,
    ui: &Ui,
    layer: &mut Vec<El>,
) -> El {
    let label = label.into();
    let toggle = key.to_owned();
    let open = s.open_menu.as_deref() == Some(key);
    let trigger = Button::new(label.clone())
        .label_with({
            let label = label.clone();
            move |font, ink| {
                row()
                    .w_full()
                    .gap(6.0)
                    .center_y()
                    .child(
                        text(label)
                            .font(font)
                            .color(ink)
                            .truncate()
                            .grow(1.0)
                            .min_w(0.0),
                    )
                    .child(icon(&icons::CHEVRON_DOWN, 12.0).color(ink))
            }
        })
        .disabled(disabled)
        .expanded(open)
        .on_press(move |s: &mut Workspace| {
            s.open_menu = if s.open_menu.as_deref() == Some(toggle.as_str()) {
                None
            } else {
                Some(toggle.clone())
            };
        })
        .build(&ui.k)
        .key(key.to_owned());
    let trigger = match width {
        Some(width) => trigger.w(width),
        None => trigger,
    };
    let mut menu = Menu::new(format!("{key}-menu"))
        .trigger(trigger)
        .open(open && !disabled)
        .on_close(|s: &mut Workspace| s.open_menu = None);
    for choice in choices {
        let action = choice.action;
        let mut item = MenuItem::new(choice.label).on_select(move |s: &mut Workspace| {
            s.open_menu = None;
            action(s);
        });
        if choice.checked {
            item = item.checked(true);
        }
        menu = menu.item(item);
    }
    menu.build(&ui.k, layer)
}

pub(crate) fn font_text(
    value: impl Into<String>,
    size: f32,
    weight: f32,
    color: Color,
    ui: &Ui,
) -> El {
    text(value.into()).font(ui.font(size, weight)).color(color)
}

/// Muted 11 pt text, the app's captions.
pub(crate) fn caption(value: impl Into<String>, ui: &Ui) -> El {
    font_text(value, 11.0, 400.0, ui.p.muted, ui)
}

/// A one-pixel rule across its parent.
pub(crate) fn rule(p: Palette) -> El {
    el().w_full().h(1.0).fill(p.line).a11y_hidden()
}

/// A one-pixel rule down its parent.
pub(crate) fn vertical_rule(p: Palette) -> El {
    el().w(1.0).h_full().fill(p.line).a11y_hidden()
}

/// A page that has not been built yet.
pub(crate) fn placeholder(title: &str, ui: &Ui) -> El {
    col()
        .key("placeholder")
        .w_full()
        .padding(40.0)
        .center()
        .child(font_text(
            format!("{title} is not available yet."),
            13.0,
            400.0,
            ui.p.muted,
            ui,
        ))
}

/// Small pill for a status such as "Recording" or "Healthy".
pub(crate) fn status_pill(label: impl Into<String>, color: Color, ui: &Ui) -> El {
    let label = label.into();
    row()
        .label(label.clone())
        .gap(6.0)
        .px(10.0)
        .py(4.0)
        .center_y()
        .radius(999.0)
        .fill(color.alpha(0.14))
        .child(el().size(6.0, 6.0).radius(3.0).fill(color).a11y_hidden())
        .child(font_text(label, 11.0, 400.0, color, ui).a11y_hidden())
}

/// A button that copies `value` and says so in the status bar.
pub(crate) fn copy_button(key: impl Into<String>, label: &str, value: String, ui: &Ui) -> El {
    Button::new(label.to_owned())
        .variant(ButtonVariant::Ghost)
        .on_press_tx(move |s: &mut Workspace, tx: &mut Tx| {
            tx.copy(value.clone());
            s.message = "Copied".into();
            s.failed = false;
        })
        .build(&ui.k)
        .key(key.into())
}

/// The status line: announced politely, or assertively when it reports a failure.
pub(crate) fn status_text(key: &str, message: &str, failed: bool, ui: &Ui) -> El {
    text(message.to_owned())
        .key(key.to_owned())
        .role(if failed { "alert" } else { "status" })
        .live_region(if message.is_empty() {
            LiveRegion::Off
        } else if failed {
            LiveRegion::Assertive
        } else {
            LiveRegion::Polite
        })
        .font(ui.font(11.0, 400.0))
        .color(if failed { ui.p.danger } else { ui.p.muted })
        .truncate()
}

fn badge(count: usize, selected: bool, ui: &Ui) -> El {
    let color = if selected { ui.p.accent } else { ui.p.muted };
    font_text(count.to_string(), 11.0, 400.0, color, ui)
        .px(8.0)
        .radius(999.0)
        .fill(color.alpha(0.12))
}

fn section_heading(label: impl Into<String>, ui: &Ui) -> El {
    font_text(label, 11.0, SEMIBOLD, ui.p.muted, ui)
        .px(8.0)
        .py(8.0)
        .truncate()
}

/// A sidebar button that is not a page tab, laid out like a navigation item.
fn sidebar_action(
    key: &'static str,
    label: &'static str,
    glyph: &'static Icon,
    disabled: bool,
    action: impl Fn(&mut Workspace) + 'static,
    ui: &Ui,
) -> El {
    let mut item = row()
        .key(key)
        .role("button")
        .label(label)
        .focusable(!disabled)
        .disabled(disabled)
        .w_full()
        .h(30.0)
        .px(8.0)
        .gap(8.0)
        .center_y()
        .radius(6.0)
        .hover(ui.k.c.hover)
        .child(icon(glyph, 15.0).color(ui.p.muted))
        .child(
            font_text(label, 13.0, 400.0, ui.p.text, ui)
                .grow(1.0)
                .truncate(),
        );
    if disabled {
        item = item.dim(0.5);
    } else {
        item = item.on_press(action);
    }
    item
}

impl Workspace {
    fn navigation_item(
        &self,
        tab: Tab,
        label: &'static str,
        glyph: &'static Icon,
        count: Option<usize>,
        ui: &Ui,
    ) -> El {
        let p = ui.p;
        let selected = self.tab == tab;
        let mut item = row()
            .key(format!("nav-{label}"))
            .role("tab")
            .label(label)
            .checked(selected)
            .focusable(!self.busy)
            .disabled(self.busy)
            .w_full()
            .h(30.0)
            .px(8.0)
            .gap(8.0)
            .center_y()
            .radius(6.0)
            .fill(if selected {
                p.selected
            } else {
                Color::TRANSPARENT
            })
            .child(icon(glyph, 15.0).color(if selected { p.accent } else { p.muted }))
            .child(
                font_text(label, 13.0, 400.0, p.text, ui)
                    .grow(1.0)
                    .truncate(),
            );
        if !selected {
            item = item.hover(ui.k.c.hover);
        }
        if let Some(count) = count {
            item = item.child(badge(count, selected, ui));
        }
        item.on_press(move |s: &mut Workspace| s.show_tab(tab))
    }

    fn sidebar(&self, ui: &Ui) -> El {
        let mut sidebar = col()
            .key("sidebar")
            .role("tablist")
            .label("Pages")
            .w(226.0)
            .h_full()
            .px(8.0)
            .py(16.0)
            .fill(ui.p.sidebar);
        if let Some(directory) = self.directory() {
            let settings = &directory.environment.settings;
            sidebar = sidebar
                .child(section_heading(directory.environment.name.clone(), ui))
                .child(self.navigation_item(
                    Tab::Users,
                    "Users",
                    &icons::USER,
                    Some(directory.users.len()),
                    ui,
                ))
                .child(self.navigation_item(
                    Tab::Groups,
                    "Groups",
                    &icons::USERS,
                    Some(directory.groups.len()),
                    ui,
                ));
            if settings.supports_oidc() {
                sidebar = sidebar.child(self.navigation_item(
                    Tab::Oidc,
                    "OIDC Inspector",
                    &icons::ID_CARD,
                    None,
                    ui,
                ));
            }
            if settings.supports_saml() {
                sidebar = sidebar.child(self.navigation_item(
                    Tab::Saml,
                    "SAML Inspector",
                    &icons::ID_CARD,
                    None,
                    ui,
                ));
            }
            if settings.scim_enabled {
                sidebar = sidebar.child(self.navigation_item(
                    Tab::Scim,
                    "SCIM provisioning",
                    &icons::ENVIRONMENTS,
                    None,
                    ui,
                ));
            }
            if settings.supports_oidc() || settings.supports_saml() {
                sidebar = sidebar.child(self.navigation_item(
                    Tab::Resilience,
                    "Fault Injection",
                    &icons::SHIELD,
                    None,
                    ui,
                ));
            }
            sidebar = sidebar
                .child(self.navigation_item(
                    Tab::Lifecycle,
                    "Lifecycle",
                    &icons::LIFECYCLE,
                    None,
                    ui,
                ))
                .child(sidebar_action(
                    "environment-settings",
                    "Set up this environment",
                    &icons::ENVIRONMENTS,
                    self.busy,
                    |s: &mut Workspace| {
                        let environment =
                            s.directory().map(|directory| directory.environment.clone());
                        s.edit_environment(environment.as_ref());
                    },
                    ui,
                ))
                .child(sidebar_action(
                    "bulk-tools",
                    "Bulk tools",
                    &icons::TOOLS,
                    self.busy,
                    |s: &mut Workspace| s.open_tools(),
                    ui,
                ));
        }
        sidebar
            .child(section_heading("Global", ui).mt(20.0))
            .child(self.navigation_item(
                Tab::Environments,
                "Environments",
                &icons::ENVIRONMENTS,
                Some(self.directories.len()),
                ui,
            ))
            .child(sidebar_action(
                "idp-tunnel",
                "IDP & tunnel",
                &icons::GLOBE,
                self.busy,
                |s: &mut Workspace| s.open_idp(),
                ui,
            ))
            .child(self.navigation_item(Tab::Traffic, "Traffic", &icons::PULSE, None, ui))
    }

    fn toolbar(&self, ui: &Ui, layer: &mut Vec<El>) -> El {
        let k = &ui.k;
        let selected_name = self
            .directory()
            .map(|directory| directory.environment.name.clone())
            .unwrap_or_else(|| "No environments".into());
        let signed_in =
            self.tunnel_snapshot.connected && !self.tunnel_snapshot.github_login.is_empty();
        let choices = self
            .directories
            .iter()
            .map(|directory| {
                let id = directory.environment.id.clone();
                Choice::new(
                    directory.environment.name.clone(),
                    move |s: &mut Workspace| s.select_environment(id.clone()),
                )
                .checked(self.selected.as_deref() == Some(directory.environment.id.as_str()))
            })
            .collect();
        let mut logo = el()
            .key("app-icon")
            .size(24.0, 24.0)
            .radius(6.0)
            .a11y_hidden();
        if let Some(image) = &self.app_icon {
            logo = logo.pixels(image.pixels());
        }
        let mut toolbar = row()
            .key("toolbar")
            .w_full()
            .h(52.0)
            .px(16.0)
            .gap(8.0)
            .center_y()
            .fill(ui.p.toolbar)
            .child(logo)
            .child(font_text("scimtest", 13.0, SEMIBOLD, ui.p.text, ui))
            .child(el().grow(1.0));
        if self.updates.available() {
            toolbar = toolbar.child(self.updates.button(ui));
        }
        toolbar = toolbar
            .child(caption("Active environment", ui))
            .child(
                dropdown(
                    self,
                    "environment-picker",
                    selected_name.clone(),
                    Some(190.0),
                    self.busy || self.directories.is_empty(),
                    choices,
                    ui,
                    layer,
                )
                .label(format!("Active environment: {selected_name}")),
            )
            .child(
                Button::new("Manage")
                    .variant(ButtonVariant::Ghost)
                    .disabled(self.busy)
                    .on_press(|s: &mut Workspace| {
                        s.tab = Tab::Environments;
                        s.message.clear();
                    })
                    .build(k)
                    .key("manage-environments"),
            )
            .child(el().grow(1.0));
        let account_label = if signed_in {
            format!("Signed in as @{}", self.tunnel_snapshot.github_login)
        } else {
            "Account & connection".to_owned()
        };
        toolbar = toolbar.child(
            Button::new(account_label)
                .variant(ButtonVariant::Ghost)
                .on_press(|s: &mut Workspace| {
                    s.account_open = true;
                    s.message.clear();
                    s.failed = false;
                })
                .build(k)
                .key("account-settings"),
        );
        if signed_in {
            toolbar = toolbar.child(
                Button::new("Log out")
                    .variant(ButtonVariant::Outline)
                    .disabled(self.busy || self.account_busy)
                    .on_press(|s: &mut Workspace| s.sign_out_account())
                    .build(k)
                    .key("sign-out"),
            );
        }
        toolbar
    }

    fn page_header(&self, ui: &Ui, layer: &mut Vec<El>) -> El {
        let p = ui.p;
        let environment = self
            .directory()
            .map(|directory| directory.environment.name.clone())
            .unwrap_or_default();
        let (title, glyph, subtitle): (&str, &'static Icon, String) = match self.tab {
            Tab::Lifecycle => (
                "Lifecycle",
                &icons::LIFECYCLE,
                format!(
                    "Run joiner, mover, and leaver scenarios against {environment} and see what it did with each message."
                ),
            ),
            Tab::Users => (
                "Users",
                &icons::USER,
                self.directory()
                    .map(|directory| format!("Users in {}.", directory.environment.name))
                    .unwrap_or_else(|| "Create an environment before adding users.".into()),
            ),
            Tab::Groups => (
                "Groups",
                &icons::USERS,
                self.directory()
                    .map(|directory| format!("Groups in {}.", directory.environment.name))
                    .unwrap_or_else(|| "Create an environment before adding groups.".into()),
            ),
            Tab::Scim => (
                "SCIM provisioning",
                &icons::ENVIRONMENTS,
                "Provision directory changes, reconcile remote state, and inspect requests.".into(),
            ),
            Tab::Oidc => (
                "OIDC Inspector",
                &icons::ID_CARD,
                format!("Authorization, token, and userinfo activity for {environment}."),
            ),
            Tab::Saml => (
                "SAML Inspector",
                &icons::ID_CARD,
                "Inspect assertions, exercise validation, and test single logout.".into(),
            ),
            Tab::Environments => (
                "Environments",
                &icons::ENVIRONMENTS,
                "Each environment is one app you are testing. Use Test sign-in to run a flow, Inspect flow to debug it, or Set up to find connection values.".into(),
            ),
            Tab::Resilience => (
                "Fault Injection",
                &icons::SHIELD,
                format!("Test how {environment} handles identity infrastructure failures."),
            ),
            Tab::Traffic => (
                "Traffic",
                &icons::PULSE,
                "Live OIDC and SAML request and response transcripts for debugging sign-in flows."
                    .into(),
            ),
        };
        row()
            .key("page-header")
            .w_full()
            .gap(16.0)
            .mb(24.0)
            .center_y()
            .child(
                el().size(44.0, 44.0)
                    .center()
                    .radius(11.0)
                    .fill(p.accent)
                    .shadow(2.0, 6.0, Color::BLACK.alpha(0.18))
                    .a11y_hidden()
                    .child(icon(glyph, 22.0).color(Color::WHITE)),
            )
            .child(
                col()
                    .grow(1.0)
                    .min_w(0.0)
                    .gap(4.0)
                    .child(
                        font_text(title, 25.0, BOLD, p.strong, ui)
                            .key("page-title")
                            .role("heading")
                            .level(1),
                    )
                    .child(font_text(subtitle, 13.0, 400.0, p.muted, ui).wrap()),
            )
            .child(self.header_actions(ui, layer))
    }

    fn header_actions(&self, ui: &Ui, _layer: &mut Vec<El>) -> El {
        let k = &ui.k;
        let p = ui.p;
        let no_environment = self.selected.is_none();
        let primary = |label: &'static str, disabled: bool, action: fn(&mut Workspace)| {
            Button::new(label)
                .variant(ButtonVariant::Contrast)
                .disabled(disabled)
                .on_press(action)
                .build(k)
                .key("add-entry")
        };
        match self.tab {
            Tab::Users => primary("+ Add user", self.busy || no_environment, |s| {
                s.edit_user(None)
            }),
            Tab::Groups => primary("+ Add group", self.busy || no_environment, |s| {
                s.edit_group(None)
            }),
            Tab::Environments => {
                primary("+ Add environment", self.busy, |s| s.edit_environment(None))
            }
            Tab::Oidc => row()
                .gap(8.0)
                .child(
                    Button::new("Test with built-in RP")
                        .variant(ButtonVariant::Contrast)
                        .disabled(self.busy || no_environment)
                        .on_press(|s: &mut Workspace| s.run_oidc())
                        .build(k)
                        .key("run-oidc"),
                )
                .child(
                    Button::new("Fault Injection")
                        .variant(ButtonVariant::Outline)
                        .disabled(self.busy || no_environment)
                        .on_press(|s: &mut Workspace| {
                            s.tab = Tab::Resilience;
                            s.refresh_identity();
                        })
                        .build(k)
                        .key("open-faults"),
                ),
            Tab::Saml => primary("Run sign-in", self.busy || no_environment, |s| s.run_saml()),
            Tab::Scim => primary(
                "Sync changes",
                self.busy || self.scim_running() || no_environment,
                |s| s.scim_action("sync", None),
            ),
            Tab::Resilience => {
                let active = self.resilience_active();
                let mut actions = row().gap(8.0).center_y();
                if active {
                    actions = actions.child(
                        Button::new("Disarm scenario")
                            .variant(ButtonVariant::Outline)
                            .disabled(self.busy)
                            .on_press(|s: &mut Workspace| s.disarm_resilience())
                            .build(k)
                            .key("add-entry"),
                    );
                }
                actions.child(if active {
                    status_pill("Scenario armed", p.accent, ui)
                } else {
                    status_pill("Healthy", p.success, ui)
                })
            }
            Tab::Traffic => {
                if self.traffic.snapshot.record {
                    status_pill("Recording", p.success, ui)
                } else {
                    status_pill("Not recording", p.muted, ui)
                }
            }
            Tab::Lifecycle => el(),
        }
    }

    fn page(&self, ui: &Ui, layer: &mut Vec<El>) -> El {
        match self.tab {
            Tab::Lifecycle => self.lifecycle_inspector(ui, layer),
            Tab::Resilience => self.resilience_inspector(ui, layer),
            Tab::Traffic => self.traffic_inspector(ui, layer),
            Tab::Scim => self.scim_inspector(ui, layer),
            Tab::Oidc => self.oidc_inspector(ui, layer),
            Tab::Saml => self.saml_inspector(ui, layer),
            Tab::Users | Tab::Groups | Tab::Environments => self.table(ui, layer),
        }
    }

    fn status_bar(&self, ui: &Ui) -> El {
        let p = ui.p;
        let idp_base = self
            .tunnel_snapshot
            .public_url
            .clone()
            .unwrap_or_else(|| self.api_url.clone());
        let mut bar = row()
            .key("status-bar")
            .w_full()
            .h(34.0)
            .px(20.0)
            .gap(20.0)
            .center_y()
            .fill(p.toolbar)
            .child(
                row()
                    .gap(6.0)
                    .center_y()
                    .child(
                        el().size(6.0, 6.0)
                            .radius(3.0)
                            .fill(p.success)
                            .a11y_hidden(),
                    )
                    .child(caption("scimtest", ui)),
            )
            .child(
                status_text(
                    "workspace-status",
                    &self.message,
                    self.failed && !self.message.is_empty(),
                    ui,
                )
                .grow(1.0)
                .min_w(0.0),
            );
        if let Some(directory) = self.directory() {
            bar = bar.child(caption(
                format!(
                    "{} SCIM: {}",
                    directory.environment.name,
                    if directory.environment.settings.scim_enabled {
                        "enabled"
                    } else {
                        "disabled"
                    }
                ),
                ui,
            ));
        }
        bar.child(caption(format!("IDP base: {idp_base}"), ui))
    }
}

pub fn view(s: &Workspace, cx: &mut Cx<Workspace>) -> El {
    let ui = Ui::new(cx.system_dark());
    let p = ui.p;
    let mut layer = Vec::new();
    let body = if s.account_locked() || s.account_open {
        s.account_screen(&ui, &mut layer)
    } else {
        let page = col()
            .key("page")
            .grow(1.0)
            .min_w(0.0)
            .h_full()
            .min_h(0.0)
            .pl(50.0)
            .pr(50.0)
            .pt(30.0)
            .pb(24.0)
            .child(s.page_header(&ui, &mut layer))
            .child(s.page(&ui, &mut layer).grow(1.0).min_h(0.0));
        col()
            .key("workspace")
            .w_full()
            .h_full()
            .fill(p.canvas)
            .child(s.toolbar(&ui, &mut layer))
            .child(rule(p))
            .child(
                row()
                    .key("main")
                    .w_full()
                    .grow(1.0)
                    .min_h(0.0)
                    .child(s.sidebar(&ui))
                    .child(vertical_rule(p))
                    .child(page),
            )
            .child(rule(p))
            .child(s.status_bar(&ui))
    };
    s.editor(&ui, &mut layer);
    s.discard_confirmation(&ui, &mut layer);
    rune_kit::root(body.font(ui.k.ty.ui).color(p.text), layer)
}
