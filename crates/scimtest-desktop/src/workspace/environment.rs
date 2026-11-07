use crate::dropdown::DropdownMenu;
use std::collections::BTreeMap;

use gpui::{AppContext, Context, Div, Entity, SharedString, Window, div, prelude::*, px};
use gpui_component::{
    Disableable, Selectable, StyledExt,
    button::{Button, ButtonVariants},
    checkbox::Checkbox,
    input::{AnyInputState, Input, InputState, Textarea, TextareaState},
    menu::PopupMenuItem,
    switch::Switch,
};
use scimtest_core::{Error, configuration::SettingsPatch, model::Environment};
use serde_json::{Value, json};

use super::{Editor, Workspace, view::icon};
use crate::theme::Palette;

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Section {
    General,
    Oidc,
    Saml,
    Scim,
    Review,
}

impl Section {
    /// The wizard steps, in order.
    pub(super) const STEPS: [(Section, &'static str); 5] = [
        (Section::General, "Environment"),
        (Section::Oidc, "OIDC"),
        (Section::Saml, "SAML"),
        (Section::Scim, "SCIM"),
        (Section::Review, "Review"),
    ];

    pub(super) fn index(self) -> usize {
        Self::STEPS
            .iter()
            .position(|(section, _)| *section == self)
            .unwrap_or_default()
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Text,
    Secret,
    Lines,
    Choice(&'static [(&'static str, &'static str)]),
    Number,
}

struct TextField {
    key: &'static str,
    label: &'static str,
    kind: Kind,
}

const TEXT_FIELDS: &[TextField] = &[
    TextField {
        key: "chooser_mode",
        label: "Sign-in chooser privacy",
        kind: Kind::Choice(&[
            ("list", "Show active users"),
            ("identifier", "Identifier mode"),
        ]),
    },
    TextField {
        key: "persona",
        label: "Provider persona",
        kind: Kind::Choice(&[
            ("generic", "Generic"),
            ("entra", "Entra ID"),
            ("okta", "Okta"),
            ("google", "Google Workspace"),
        ]),
    },
    TextField {
        key: "groups_overage_threshold",
        label: "Entra ID groups overage threshold",
        kind: Kind::Number,
    },
    TextField {
        key: "oidc_client_id",
        label: "Client ID",
        kind: Kind::Text,
    },
    TextField {
        key: "oidc_client_secret",
        label: "Client secret",
        kind: Kind::Secret,
    },
    TextField {
        key: "oidc_redirect_uris",
        label: "Redirect URIs",
        kind: Kind::Lines,
    },
    TextField {
        key: "oidc_access_token_audience",
        label: "Access token audience",
        kind: Kind::Text,
    },
    TextField {
        key: "oidc_backchannel_logout_uri",
        label: "Back-channel logout URI",
        kind: Kind::Text,
    },
    TextField {
        key: "oidc_claim_mappings.name",
        label: "Name claim",
        kind: Kind::Text,
    },
    TextField {
        key: "oidc_claim_mappings.given_name",
        label: "Given name claim",
        kind: Kind::Text,
    },
    TextField {
        key: "oidc_claim_mappings.family_name",
        label: "Family name claim",
        kind: Kind::Text,
    },
    TextField {
        key: "oidc_claim_mappings.username",
        label: "Username claim",
        kind: Kind::Text,
    },
    TextField {
        key: "oidc_claim_mappings.email",
        label: "Email claim",
        kind: Kind::Text,
    },
    TextField {
        key: "oidc_claim_mappings.groups",
        label: "Groups claim",
        kind: Kind::Text,
    },
    TextField {
        key: "saml_entity_id",
        label: "SP entity ID",
        kind: Kind::Text,
    },
    TextField {
        key: "saml_acs_url",
        label: "ACS URL",
        kind: Kind::Text,
    },
    TextField {
        key: "saml_slo_url",
        label: "Single Logout URL",
        kind: Kind::Text,
    },
    TextField {
        key: "saml_audience",
        label: "Audience",
        kind: Kind::Text,
    },
    TextField {
        key: "saml_name_id_field",
        label: "NameID field",
        kind: Kind::Choice(&[
            ("email", "Email"),
            ("username", "Username"),
            ("firstName", "First name"),
            ("lastName", "Last name"),
        ]),
    },
    TextField {
        key: "saml_attribute_mappings.email",
        label: "Email attribute assertion name",
        kind: Kind::Text,
    },
    TextField {
        key: "saml_signing_mode",
        label: "Signing",
        kind: Kind::Choice(&[
            ("assertion", "Sign assertion"),
            ("response", "Sign response"),
            ("both", "Sign response and assertion"),
        ]),
    },
    TextField {
        key: "saml_request_certificate_pem",
        label: "SP request-signing certificate (PEM)",
        kind: Kind::Lines,
    },
    TextField {
        key: "saml_encryption_certificate_pem",
        label: "SP assertion-encryption certificate (PEM)",
        kind: Kind::Lines,
    },
    TextField {
        key: "saml_encryption_algorithm",
        label: "Assertion encryption",
        kind: Kind::Choice(&[
            ("aes128-gcm", "AES-128-GCM"),
            ("aes192-gcm", "AES-192-GCM"),
            ("aes256-gcm", "AES-256-GCM"),
        ]),
    },
    TextField {
        key: "saml_attribute_mappings.given_name",
        label: "Given name attribute",
        kind: Kind::Text,
    },
    TextField {
        key: "saml_attribute_mappings.family_name",
        label: "Family name attribute",
        kind: Kind::Text,
    },
    TextField {
        key: "saml_attribute_mappings.username",
        label: "Username attribute",
        kind: Kind::Text,
    },
    TextField {
        key: "saml_attribute_mappings.groups",
        label: "Groups attribute",
        kind: Kind::Text,
    },
    TextField {
        key: "scim_base_url",
        label: "SCIM base URL",
        kind: Kind::Text,
    },
    TextField {
        key: "scim_bearer_token",
        label: "Bearer token",
        kind: Kind::Secret,
    },
];

/// Boolean settings. Each key is an option stored in `toggles`.
const TOGGLE_KEYS: &[&str] = &[
    "include_groups_claim",
    "oidc_enabled",
    "oidc_public_client",
    "allow_any_oidc_redirect",
    "oidc_jwt_access_tokens",
    "oidc_backchannel_logout_session_required",
    "regenerate_oidc_secret",
    "saml_enabled",
    "scim_enabled",
    "scim_auto_open_trace",
];

/// The field's help text, shown beneath its control.
fn hint(key: &str) -> &'static str {
    match key {
        "chooser_mode" => "Identifier mode prevents the sign-in page from listing directory users.",
        "persona" => {
            "Shapes OIDC claims like the real provider. Entra ID also changes SCIM requests."
        }
        "groups_overage_threshold" => {
            "Above this many groups, Entra ID tokens point to an overage endpoint instead of listing groups. 0 uses the provider default."
        }
        "oidc_client_id" => "Use this same value in your app's OIDC configuration.",
        "oidc_redirect_uris" => {
            "Where scimtest may send the browser after sign-in. Enter one absolute HTTP(S) URI per line."
        }
        "oidc_backchannel_logout_uri" => {
            "When an IdP session ends, scimtest POSTs a signed logout token here. It must be reachable from this machine."
        }
        "saml_entity_id" => "The unique SAML identifier configured by your app.",
        "saml_acs_url" => "Where scimtest should post the signed SAML response after sign-in.",
        "saml_slo_url" => {
            "Where scimtest sends LogoutRequest and LogoutResponse messages. Leave empty if your app has no Single Logout."
        }
        "saml_name_id_field" => "NameID format is inferred from this value.",
        "saml_attribute_mappings.email" => "Use the value expected by the relying party.",
        "scim_base_url" => {
            "The SCIM endpoint provided by the app you are testing, usually ending in /scim/v2."
        }
        "scim_bearer_token" => {
            "The credential scimtest should use when calling the app's SCIM API."
        }
        _ => "",
    }
}

/// The checkbox help text, shown beneath its label.
fn toggle_hint(key: &str) -> &'static str {
    match key {
        "allow_any_oidc_redirect" => {
            "Ignored on the public tunnel while connected; register exact redirect URIs instead."
        }
        _ => "",
    }
}

pub(super) struct EnvironmentForm {
    pub section: Section,
    text: BTreeMap<&'static str, AnyInputState>,
    pub(super) toggles: BTreeMap<&'static str, bool>,
}

impl EnvironmentForm {
    pub fn inputs(&self) -> Vec<AnyInputState> {
        self.text.values().cloned().collect()
    }

    pub fn new(
        environment: Option<&Environment>,
        window: &mut Window,
        cx: &mut Context<Workspace>,
    ) -> Result<Self, Error> {
        let settings = environment
            .map(|environment| environment.settings.clone())
            .unwrap_or_default();
        let values = serde_json::to_value(&settings)?;
        let mut text = BTreeMap::new();
        for field in TEXT_FIELDS {
            let value = match field.key.split_once('.') {
                Some((parent, name)) => &values[parent][name],
                None => &values[field.key],
            };
            let mut value = match value {
                Value::String(value) => value.clone(),
                Value::Number(value) => value.to_string(),
                Value::Array(values) => values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("\n"),
                _ => String::new(),
            };
            if value.is_empty() {
                value = match field.key {
                    "saml_encryption_algorithm" => "aes256-gcm",
                    "saml_signing_mode" => "assertion",
                    "groups_overage_threshold" => "0",
                    _ => "",
                }
                .into();
            }
            let state = if matches!(field.kind, Kind::Lines) {
                AnyInputState::Textarea(cx.new(|cx| {
                    let mut state = TextareaState::new(window, cx).auto_grow(3, 6);
                    state.set_value(value, window, cx);
                    state
                }))
            } else {
                AnyInputState::Input(cx.new(|cx| {
                    let mut state = InputState::new(window, cx);
                    if matches!(field.kind, Kind::Secret) {
                        state = state.masked(true);
                    }
                    state.set_value(value, window, cx);
                    state
                }))
            };
            text.insert(field.key, state);
        }
        let mut toggles = TOGGLE_KEYS
            .iter()
            .map(|key| (*key, values[*key].as_bool().unwrap_or(false)))
            .collect::<BTreeMap<_, _>>();
        toggles.insert("oidc_enabled", settings.supports_oidc());
        toggles.insert("saml_enabled", settings.supports_saml());
        toggles.insert(
            "scim_enabled",
            settings.scim_enabled
                || !settings.scim_base_url.is_empty()
                || !settings.scim_bearer_token.is_empty(),
        );
        Ok(Self {
            section: Section::General,
            text,
            toggles,
        })
    }

    pub fn patch(&self, cx: &Context<Workspace>) -> Result<SettingsPatch, Error> {
        let mut values = json!({});
        for (key, enabled) in &self.toggles {
            values[*key] = json!(enabled);
        }
        for field in TEXT_FIELDS {
            let value = self.text[field.key].value(cx).to_string();
            let value = match field.kind {
                Kind::Number if value.trim().is_empty() => json!(0),
                Kind::Number => {
                    json!(value.trim().parse::<i64>().map_err(|_| Error::Validation(
                        "groups overage threshold must be a whole number".into()
                    ))?)
                }
                Kind::Lines if field.key == "oidc_redirect_uris" => json!(
                    value
                        .lines()
                        .map(str::trim)
                        .filter(|line| !line.is_empty())
                        .collect::<Vec<_>>()
                ),
                _ => json!(value),
            };
            match field.key.split_once('.') {
                Some((parent, name)) => values[parent][name] = value,
                None => values[field.key] = value,
            }
        }
        Ok(serde_json::from_value(values)?)
    }

    /// The wizard's step bar and the current step's content.
    pub fn body(
        &self,
        workspace: &Workspace,
        name: &Entity<InputState>,
        slug: &Entity<InputState>,
        id: Option<&str>,
        cx: &mut Context<Workspace>,
    ) -> Div {
        let mut body = div().v_flex().gap_5().child(self.steps(cx));
        body = match self.section {
            Section::General => body.child(self.general(workspace, name, slug, cx)),
            Section::Oidc => body.child(self.oidc(workspace, cx)),
            Section::Saml => body.child(self.saml(workspace, cx)),
            Section::Scim => body.child(self.scim(workspace, id.is_some(), cx)),
            Section::Review => body.child(self.review(workspace, name, slug, id, cx)),
        };
        body
    }

    /// Previous and next buttons for moving through the wizard.
    pub fn nav(&self, cx: &mut Context<Workspace>) -> Div {
        let index = self.section.index();
        let last = Section::STEPS.len() - 1;
        div()
            .h_flex()
            .gap_2()
            .when(index > 0, |row| {
                row.child(
                    Button::new("wizard-previous")
                        .label("Previous")
                        .h(px(29.))
                        .outline()
                        .on_click(cx.listener(move |view, _, _, cx| {
                            view.set_environment_step(index - 1, cx)
                        })),
                )
            })
            .when(index < last, |row| {
                row.child(
                    Button::new("wizard-next")
                        .label("Next")
                        .h(px(29.))
                        .primary()
                        .on_click(cx.listener(move |view, _, _, cx| {
                            view.set_environment_step(index + 1, cx)
                        })),
                )
            })
    }

    fn steps(&self, cx: &mut Context<Workspace>) -> Div {
        let palette = Palette::get(cx);
        let mut bar = div()
            .h_flex()
            .gap_1()
            .p_1()
            .rounded_md()
            .bg(palette.soft)
            .flex_wrap();
        for (index, (section, label)) in Section::STEPS.into_iter().enumerate() {
            let current = self.section == section;
            let enabled = match section {
                Section::Oidc => self.toggle("oidc_enabled"),
                Section::Saml => self.toggle("saml_enabled"),
                Section::Scim => self.toggle("scim_enabled"),
                _ => false,
            };
            let text = if enabled {
                format!("{} {label} ✓", index + 1)
            } else {
                format!("{} {label}", index + 1)
            };
            bar = bar.child(
                Button::new(SharedString::from(format!("step-{index}")))
                    .accessibility_label(format!("Step {}: {label}", index + 1))
                    .label(text)
                    .h(px(29.))
                    .ghost()
                    .selected(current)
                    .toggled(current)
                    .when(current, |button| button.bg(palette.card))
                    .on_click(
                        cx.listener(move |view, _, _, cx| view.set_environment_step(index, cx)),
                    ),
            );
        }
        bar
    }

    fn general(
        &self,
        workspace: &Workspace,
        name: &Entity<InputState>,
        slug: &Entity<InputState>,
        cx: &mut Context<Workspace>,
    ) -> Div {
        let palette = Palette::get(cx);
        div()
            .v_flex()
            .gap_4()
            .child(section_title(
                "Environment",
                "Name this test environment and choose the shared sign-in behavior.",
                palette,
            ))
            .child(
                div()
                    .h_flex()
                    .items_start()
                    .gap_4()
                    .child(plain_input(
                        "Environment name",
                        "Use the name of the app or integration you are testing.",
                        name,
                        cx,
                    ))
                    .child(plain_input(
                        "Endpoint name",
                        "Generated from the name and used in OIDC and SAML URLs.",
                        slug,
                        cx,
                    )),
            )
            .child(
                div()
                    .h_flex()
                    .items_start()
                    .gap_4()
                    .child(self.field("chooser_mode", workspace.busy, cx))
                    .child(self.field("persona", workspace.busy, cx)),
            )
            .child(
                div()
                    .h_flex()
                    .items_start()
                    .gap_4()
                    .child(self.field("groups_overage_threshold", workspace.busy, cx))
                    .child(div().flex_1()),
            )
            .child(self.toggle_row(
                "include_groups_claim",
                "Include groups in OIDC claims and SAML attributes",
                workspace.busy,
                cx,
            ))
    }

    fn oidc(&self, workspace: &Workspace, cx: &mut Context<Workspace>) -> Div {
        let busy = workspace.busy;
        let mut content = div().v_flex().gap_4().child(self.section_header(
            "OIDC",
            "Sign users in to your app with OpenID Connect.",
            "oidc_enabled",
            busy,
            cx,
        ));

        content = content
            .child(self.field("oidc_client_id", busy, cx))
            .child(self.field("oidc_client_secret", busy, cx))
            .child(self.toggle_row(
                "oidc_public_client",
                "Public client (no client secret)",
                busy,
                cx,
            ))
            .child(self.field("oidc_redirect_uris", busy, cx))
            .child(self.toggle_row(
                "allow_any_oidc_redirect",
                "Allow arbitrary redirect URIs",
                busy,
                cx,
            ))
            .child(self.field("oidc_backchannel_logout_uri", busy, cx))
            .child(self.toggle_row(
                "oidc_backchannel_logout_session_required",
                "Require a session ID for back-channel logout",
                busy,
                cx,
            ))
            .child(self.field("oidc_access_token_audience", busy, cx))
            .child(self.toggle_row(
                "oidc_jwt_access_tokens",
                "Issue JWT access tokens",
                busy,
                cx,
            ))
            .child(self.toggle_row(
                "regenerate_oidc_secret",
                "Generate a new client secret when saving",
                busy,
                cx,
            ))
            .child(workspace.disclosure("oidc-claims", "Claim mappings", cx));
        if workspace.disclosures.contains("oidc-claims") {
            content = content.child(
                div()
                    .v_flex()
                    .gap_4()
                    .pl_3()
                    .child(self.field_pair(
                        "oidc_claim_mappings.name",
                        "oidc_claim_mappings.given_name",
                        busy,
                        cx,
                    ))
                    .child(self.field_pair(
                        "oidc_claim_mappings.family_name",
                        "oidc_claim_mappings.username",
                        busy,
                        cx,
                    ))
                    .child(self.field_pair(
                        "oidc_claim_mappings.email",
                        "oidc_claim_mappings.groups",
                        busy,
                        cx,
                    )),
            );
        }
        content
    }

    fn saml(&self, workspace: &Workspace, cx: &mut Context<Workspace>) -> Div {
        let busy = workspace.busy;
        let mut content = div().v_flex().gap_4().child(self.section_header(
            "SAML",
            "Configure scimtest as the identity provider for your service provider.",
            "saml_enabled",
            busy,
            cx,
        ));

        content = content
            .child(
                div()
                    .h_flex()
                    .items_start()
                    .gap_4()
                    .child(self.field("saml_entity_id", busy, cx))
                    .child(self.field("saml_acs_url", busy, cx)),
            )
            .child(
                div()
                    .h_flex()
                    .items_start()
                    .gap_4()
                    .child(self.field("saml_slo_url", busy, cx))
                    .child(self.field("saml_audience", busy, cx)),
            )
            .child(self.field("saml_name_id_field", busy, cx))
            .child(self.field("saml_attribute_mappings.email", busy, cx))
            .child(workspace.disclosure("saml-signing", "Signing and Encryption", cx));
        if workspace.disclosures.contains("saml-signing") {
            content = content.child(
                div()
                    .v_flex()
                    .gap_4()
                    .pl_3()
                    .child(self.field("saml_signing_mode", busy, cx))
                    .child(self.field("saml_request_certificate_pem", busy, cx))
                    .child(self.field("saml_encryption_certificate_pem", busy, cx))
                    .child(self.field("saml_encryption_algorithm", busy, cx)),
            );
        }
        content =
            content.child(workspace.disclosure("saml-mappings", "SAML attribute mappings", cx));
        if workspace.disclosures.contains("saml-mappings") {
            content = content.child(
                div()
                    .v_flex()
                    .gap_4()
                    .pl_3()
                    .child(self.field_pair(
                        "saml_attribute_mappings.given_name",
                        "saml_attribute_mappings.family_name",
                        busy,
                        cx,
                    ))
                    .child(self.field_pair(
                        "saml_attribute_mappings.username",
                        "saml_attribute_mappings.groups",
                        busy,
                        cx,
                    )),
            );
        }
        content
    }

    fn scim(&self, workspace: &Workspace, editing: bool, cx: &mut Context<Workspace>) -> Div {
        let busy = workspace.busy;
        let mut content = div().v_flex().gap_4().child(self.section_header(
            "SCIM",
            "Provision this environment's users and groups to your app.",
            "scim_enabled",
            busy,
            cx,
        ));

        content = content
            .child(self.field("scim_base_url", busy, cx))
            .child(self.field("scim_bearer_token", busy, cx))
            .child(
                Button::new("test-scim-connection")
                    .label("Test connection")
                    .outline()
                    .h(px(29.))
                    .w_full()
                    .disabled(busy || !editing)
                    .on_click(cx.listener(|view, _, _, cx| {
                        view.scim_action("test", None, cx);
                    })),
            )
            .child(self.toggle_row(
                "scim_auto_open_trace",
                "Auto-open after sync and import",
                busy,
                cx,
            ));
        content
    }

    fn review(
        &self,
        workspace: &Workspace,
        name: &Entity<InputState>,
        slug: &Entity<InputState>,
        id: Option<&str>,
        cx: &mut Context<Workspace>,
    ) -> Div {
        let palette = Palette::get(cx);
        let name_value = name.read(cx).value().to_string();
        let slug_value = slug.read(cx).value().to_string();
        let integrations = [
            ("OIDC", "oidc_enabled"),
            ("SAML", "saml_enabled"),
            ("SCIM", "scim_enabled"),
        ];
        let mut tiles = div().h_flex().gap_3();
        for (label, key) in integrations {
            let enabled = self.toggle(key);
            tiles = tiles.child(
                div()
                    .v_flex()
                    .flex_1()
                    .gap_1()
                    .p_3()
                    .rounded_md()
                    .border_1()
                    .border_color(palette.line)
                    .child(
                        div()
                            .h_flex()
                            .justify_between()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(label)
                            .child(
                                div()
                                    .text_size(px(12.))
                                    .text_color(if enabled {
                                        palette.success
                                    } else {
                                        palette.muted
                                    })
                                    .child(if enabled { "Enabled" } else { "Disabled" }),
                            ),
                    )
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(palette.muted)
                            .child(if enabled { "Included" } else { "Not included" }),
                    ),
            );
        }
        let mut content = div()
            .v_flex()
            .gap_4()
            .child(section_title(
                "Review environment",
                "Confirm the environment and integrations before saving.",
                palette,
            ))
            .child(
                div()
                    .h_flex()
                    .gap_3()
                    .child(review_value("Environment name", &name_value, palette))
                    .child(review_value("Endpoint name", &slug_value, palette)),
            )
            .child(tiles)
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(palette.muted)
                    .child("Select an integration to make corrections, or save the environment to apply these settings."),
            );
        if let Some(id) = id {
            let copy_id = id.to_owned();
            let save_id = id.to_owned();
            content = content.child(
                div()
                    .h_flex()
                    .gap_2()
                    .child(
                        Button::new("copy-connection")
                            .label("Copy config JSON")
                            .h(px(29.))
                            .outline()
                            .disabled(workspace.busy)
                            .on_click(cx.listener(move |view, _, _, cx| {
                                view.export_connection(copy_id.clone(), false, cx)
                            })),
                    )
                    .child(
                        Button::new("save-connection")
                            .label("Save config JSON…")
                            .h(px(29.))
                            .outline()
                            .disabled(workspace.busy)
                            .on_click(cx.listener(move |view, _, _, cx| {
                                view.export_connection(save_id.clone(), true, cx)
                            })),
                    ),
            );
        }
        content
    }

    fn section_header(
        &self,
        title: &'static str,
        description: &'static str,
        key: &'static str,
        busy: bool,
        cx: &mut Context<Workspace>,
    ) -> Div {
        let palette = Palette::get(cx);
        let enabled = self.toggle(key);
        div()
            .h_flex()
            .justify_between()
            .items_start()
            .gap_4()
            .child(section_title(title, description, palette))
            .child(
                Switch::new(SharedString::from(format!("{key}-switch")))
                    .accessibility_label(format!("{title} enabled"))
                    .checked(enabled)
                    .label(if enabled { "Enabled" } else { "Disabled" })
                    .disabled(busy)
                    .on_click(cx.listener(move |view, checked: &bool, _, cx| {
                        if let Some(Editor::Environment { settings, .. }) = &mut view.editor {
                            settings.toggles.insert(key, *checked);
                            view.editor_dirty = true;
                        }
                        cx.notify();
                    })),
            )
    }

    /// The problem with `section`, if it is in use and a required value is blank.
    pub fn section_error(
        &self,
        name: &Entity<InputState>,
        section: Section,
        cx: &Context<Workspace>,
    ) -> Option<String> {
        if section == Section::General && name.read(cx).value().trim().is_empty() {
            return Some("Enter an environment name.".into());
        }
        let (label, switch, required) = match section {
            Section::General | Section::Review => return None,
            Section::Oidc => (
                "OIDC",
                "oidc_enabled",
                &[
                    ("Client ID", "oidc_client_id"),
                    ("Redirect URIs", "oidc_redirect_uris"),
                ][..],
            ),
            Section::Saml => (
                "SAML",
                "saml_enabled",
                &[
                    ("SP entity ID", "saml_entity_id"),
                    ("ACS URL", "saml_acs_url"),
                ][..],
            ),
            Section::Scim => (
                "SCIM",
                "scim_enabled",
                &[
                    ("SCIM base URL", "scim_base_url"),
                    ("Bearer token", "scim_bearer_token"),
                ][..],
            ),
        };
        if !self.toggle(switch) {
            return None;
        }
        let missing = required
            .iter()
            .filter(|(_, key)| self.is_blank(key, cx))
            .map(|(label, _)| *label)
            .collect::<Vec<_>>();
        (!missing.is_empty()).then(|| format!("{label} needs {}.", missing.join(", ")))
    }

    /// The first section, in wizard order, with a problem.
    pub fn first_error(
        &self,
        name: &Entity<InputState>,
        cx: &Context<Workspace>,
    ) -> Option<(Section, String)> {
        [
            Section::General,
            Section::Oidc,
            Section::Saml,
            Section::Scim,
        ]
        .into_iter()
        .find_map(|section| {
            self.section_error(name, section, cx)
                .map(|message| (section, message))
        })
    }

    fn is_blank(&self, key: &str, cx: &Context<Workspace>) -> bool {
        self.text
            .get(key)
            .is_none_or(|state| state.value(cx).trim().is_empty())
    }

    fn toggle(&self, key: &str) -> bool {
        self.toggles.get(key).copied().unwrap_or(false)
    }

    fn toggle_row(
        &self,
        key: &'static str,
        label: &'static str,
        busy: bool,
        cx: &mut Context<Workspace>,
    ) -> Div {
        let palette = Palette::get(cx);
        let help = toggle_hint(key);
        div()
            .v_flex()
            .gap_1()
            .child(
                Checkbox::new(key)
                    .label(label)
                    .checked(self.toggle(key))
                    .disabled(busy)
                    .on_click(cx.listener(move |view, checked: &bool, _, cx| {
                        if let Some(Editor::Environment { settings, .. }) = &mut view.editor {
                            settings.toggles.insert(key, *checked);
                            view.editor_dirty = true;
                        }
                        cx.notify();
                    })),
            )
            .when(!help.is_empty(), |column| {
                column.child(
                    div()
                        .pl_6()
                        .text_size(px(11.))
                        .text_color(palette.muted)
                        .child(help),
                )
            })
    }

    fn field_pair(
        &self,
        left: &'static str,
        right: &'static str,
        busy: bool,
        cx: &mut Context<Workspace>,
    ) -> Div {
        div()
            .h_flex()
            .items_start()
            .gap_4()
            .child(self.field(left, busy, cx))
            .child(self.field(right, busy, cx))
    }

    fn field(&self, key: &'static str, busy: bool, cx: &mut Context<Workspace>) -> Div {
        let palette = Palette::get(cx);
        let Some(field) = TEXT_FIELDS.iter().find(|field| field.key == key) else {
            return div();
        };
        let Some(state) = self.text.get(key) else {
            return div();
        };
        let help = hint(key);
        let mut column = div()
            .v_flex()
            .flex_1()
            .min_w_0()
            .gap_2()
            .child(div().text_size(px(12.)).child(field.label));
        if let Some(state) = state.as_textarea() {
            column = column.child(Textarea::new(state).aria_label(field.label).disabled(busy));
        } else if let Some(state) = state.as_input() {
            if let Kind::Choice(choices) = field.kind {
                let current = state.read(cx).value().to_string();
                let label = choices
                    .iter()
                    .find(|(value, _)| *value == current)
                    .map_or(current.as_str(), |(_, label)| *label)
                    .to_owned();
                let state = state.clone();
                let view = cx.weak_entity();
                column = column.child(
                    Button::new(key)
                        .accessibility_label(format!("{}: {label}", field.label))
                        .label(label)
                        .icon(icon("icons/chevron-down.svg"))
                        .h(px(32.))
                        .justify_between()
                        .border_1()
                        .border_color(palette.line)
                        .rounded_md()
                        .disabled(busy)
                        .dropdown_menu(move |mut menu, _, _| {
                            for (value, label) in choices {
                                let state = state.clone();
                                let view = view.clone();
                                menu = menu.item(PopupMenuItem::new(*label).on_click(
                                    move |_, window, cx| {
                                        state.update(cx, |state, cx| {
                                            state.set_value(*value, window, cx)
                                        });
                                        let _ = view.update(cx, |view, cx| {
                                            view.editor_dirty = true;
                                            cx.notify();
                                        });
                                    },
                                ));
                            }
                            menu
                        }),
                );
            } else {
                column = column.child(
                    Input::new(state)
                        .aria_label(field.label)
                        .accessibility_id(field.key)
                        .disabled(busy)
                        .when(matches!(field.kind, Kind::Secret), |input| {
                            input
                                .content_type(gpui_component::input::InputContentType::Password)
                                .mask_toggle()
                        }),
                );
            }
        }
        if !help.is_empty() {
            column = column.child(
                div()
                    .text_size(px(11.))
                    .text_color(palette.muted)
                    .child(help),
            );
        }
        column
    }
}

impl Workspace {
    /// Moves the wizard to `section` and explains why the change was blocked.
    pub(super) fn show_environment_error(
        &mut self,
        section: Section,
        message: String,
        cx: &mut Context<Self>,
    ) {
        if let Some(Editor::Environment { settings, .. }) = &mut self.editor {
            settings.section = section;
        }
        self.message = message;
        self.failed = true;
        self.status_revision = self.status_revision.wrapping_add(1);
        cx.notify();
    }
}

fn section_title(title: &'static str, description: &'static str, palette: Palette) -> Div {
    div()
        .v_flex()
        .gap_1()
        .flex_1()
        .child(
            div()
                .text_size(px(16.))
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(title),
        )
        .child(
            div()
                .text_size(px(12.))
                .text_color(palette.muted)
                .child(description),
        )
}

/// A labeled input with help text, for the general step's name fields.
fn plain_input(
    label: &'static str,
    help: &'static str,
    state: &Entity<InputState>,
    cx: &Context<Workspace>,
) -> Div {
    let palette = Palette::get(cx);
    div()
        .v_flex()
        .flex_1()
        .min_w_0()
        .gap_2()
        .child(div().text_size(px(12.)).child(label))
        .child(Input::new(state).aria_label(label))
        .child(
            div()
                .text_size(px(11.))
                .text_color(palette.muted)
                .child(help),
        )
}

fn review_value(label: &'static str, value: &str, palette: Palette) -> Div {
    div()
        .v_flex()
        .flex_1()
        .gap_1()
        .p_3()
        .rounded_md()
        .border_1()
        .border_color(palette.line)
        .child(
            div()
                .text_size(px(11.))
                .text_color(palette.muted)
                .child(label),
        )
        .child(
            div()
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(value.to_owned()),
        )
}
