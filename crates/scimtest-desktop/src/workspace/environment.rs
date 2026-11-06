use crate::dropdown::DropdownMenu;
use std::collections::BTreeMap;

use gpui::{AppContext, Context, IntoElement, Window, div, prelude::*, px};
use gpui_component::{
    Disableable, Selectable, StyledExt,
    button::Button,
    checkbox::Checkbox,
    input::{AnyInputState, Input, InputState, Textarea, TextareaState},
    menu::PopupMenuItem,
};
use scimtest_core::{Error, configuration::SettingsPatch, model::Environment};
use serde_json::{Value, json};

use super::{Editor, Workspace};

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Section {
    General,
    Oidc,
    Saml,
    Scim,
}

#[derive(Clone, Copy)]
enum Kind {
    Text,
    Secret,
    Lines,
    Choice(&'static [&'static str]),
    Number,
}

struct TextField {
    key: &'static str,
    label: &'static str,
    section: Section,
    kind: Kind,
}

const TEXT_FIELDS: &[TextField] = &[
    TextField {
        key: "chooser_mode",
        label: "Sign-in chooser",
        section: Section::General,
        kind: Kind::Choice(&["list", "identifier"]),
    },
    TextField {
        key: "persona",
        label: "Provider persona",
        section: Section::General,
        kind: Kind::Choice(&["generic", "entra", "okta", "google"]),
    },
    TextField {
        key: "groups_overage_threshold",
        label: "Entra groups overage threshold (0 uses the provider default)",
        section: Section::General,
        kind: Kind::Number,
    },
    TextField {
        key: "oidc_client_id",
        label: "Client ID",
        section: Section::Oidc,
        kind: Kind::Text,
    },
    TextField {
        key: "oidc_client_secret",
        label: "Client secret",
        section: Section::Oidc,
        kind: Kind::Secret,
    },
    TextField {
        key: "oidc_redirect_uris",
        label: "Redirect URIs (one per line)",
        section: Section::Oidc,
        kind: Kind::Lines,
    },
    TextField {
        key: "oidc_access_token_audience",
        label: "Access token audience",
        section: Section::Oidc,
        kind: Kind::Text,
    },
    TextField {
        key: "oidc_backchannel_logout_uri",
        label: "Back-channel logout URI",
        section: Section::Oidc,
        kind: Kind::Text,
    },
    TextField {
        key: "oidc_claim_mappings.name",
        label: "Name claim",
        section: Section::Oidc,
        kind: Kind::Text,
    },
    TextField {
        key: "oidc_claim_mappings.given_name",
        label: "Given name claim",
        section: Section::Oidc,
        kind: Kind::Text,
    },
    TextField {
        key: "oidc_claim_mappings.family_name",
        label: "Family name claim",
        section: Section::Oidc,
        kind: Kind::Text,
    },
    TextField {
        key: "oidc_claim_mappings.username",
        label: "Username claim",
        section: Section::Oidc,
        kind: Kind::Text,
    },
    TextField {
        key: "oidc_claim_mappings.email",
        label: "Email claim",
        section: Section::Oidc,
        kind: Kind::Text,
    },
    TextField {
        key: "oidc_claim_mappings.groups",
        label: "Groups claim",
        section: Section::Oidc,
        kind: Kind::Text,
    },
    TextField {
        key: "saml_entity_id",
        label: "SP entity ID",
        section: Section::Saml,
        kind: Kind::Text,
    },
    TextField {
        key: "saml_acs_url",
        label: "Assertion Consumer Service URL",
        section: Section::Saml,
        kind: Kind::Text,
    },
    TextField {
        key: "saml_slo_url",
        label: "Single Logout URL",
        section: Section::Saml,
        kind: Kind::Text,
    },
    TextField {
        key: "saml_audience",
        label: "Audience",
        section: Section::Saml,
        kind: Kind::Text,
    },
    TextField {
        key: "saml_name_id_field",
        label: "NameID field",
        section: Section::Saml,
        kind: Kind::Choice(&["email", "username", "firstName", "lastName"]),
    },
    TextField {
        key: "saml_signing_mode",
        label: "Sign",
        section: Section::Saml,
        kind: Kind::Choice(&["assertion", "response", "both"]),
    },
    TextField {
        key: "saml_request_certificate_pem",
        label: "SP request-signing certificate (PEM)",
        section: Section::Saml,
        kind: Kind::Lines,
    },
    TextField {
        key: "saml_encryption_certificate_pem",
        label: "SP assertion-encryption certificate (PEM)",
        section: Section::Saml,
        kind: Kind::Lines,
    },
    TextField {
        key: "saml_encryption_algorithm",
        label: "Assertion encryption",
        section: Section::Saml,
        kind: Kind::Choice(&["aes128-gcm", "aes192-gcm", "aes256-gcm"]),
    },
    TextField {
        key: "saml_attribute_mappings.given_name",
        label: "Given name attribute",
        section: Section::Saml,
        kind: Kind::Text,
    },
    TextField {
        key: "saml_attribute_mappings.family_name",
        label: "Family name attribute",
        section: Section::Saml,
        kind: Kind::Text,
    },
    TextField {
        key: "saml_attribute_mappings.username",
        label: "Username attribute",
        section: Section::Saml,
        kind: Kind::Text,
    },
    TextField {
        key: "saml_attribute_mappings.email",
        label: "Email attribute",
        section: Section::Saml,
        kind: Kind::Text,
    },
    TextField {
        key: "saml_attribute_mappings.groups",
        label: "Groups attribute",
        section: Section::Saml,
        kind: Kind::Text,
    },
    TextField {
        key: "scim_base_url",
        label: "SCIM base URL",
        section: Section::Scim,
        kind: Kind::Text,
    },
    TextField {
        key: "scim_bearer_token",
        label: "Bearer token",
        section: Section::Scim,
        kind: Kind::Secret,
    },
];

const TOGGLES: &[(&str, &str, Section)] = &[
    (
        "include_groups_claim",
        "Include groups in claims and attributes",
        Section::General,
    ),
    ("oidc_enabled", "Enable OpenID Connect", Section::Oidc),
    (
        "oidc_public_client",
        "Public client (PKCE required)",
        Section::Oidc,
    ),
    (
        "allow_any_oidc_redirect",
        "Allow any HTTP(S) redirect URI",
        Section::Oidc,
    ),
    (
        "oidc_jwt_access_tokens",
        "Issue JWT access tokens",
        Section::Oidc,
    ),
    (
        "oidc_backchannel_logout_session_required",
        "Require a session ID for back-channel logout",
        Section::Oidc,
    ),
    (
        "regenerate_oidc_secret",
        "Generate a new client secret when saving",
        Section::Oidc,
    ),
    ("saml_enabled", "Enable SAML", Section::Saml),
    ("scim_enabled", "Enable SCIM provisioning", Section::Scim),
    (
        "scim_auto_open_trace",
        "Open the trace after syncing",
        Section::Scim,
    ),
];

pub(super) struct EnvironmentForm {
    pub section: Section,
    text: BTreeMap<&'static str, AnyInputState>,
    toggles: BTreeMap<&'static str, bool>,
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
        let mut toggles = TOGGLES
            .iter()
            .map(|(key, _, _)| (*key, values[*key].as_bool().unwrap_or(false)))
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

    pub fn tabs(&self, cx: &mut Context<Workspace>) -> impl IntoElement {
        div().h_flex().gap_2().children(
            [
                (Section::General, "General"),
                (Section::Oidc, "OIDC"),
                (Section::Saml, "SAML"),
                (Section::Scim, "SCIM"),
            ]
            .into_iter()
            .map(|(section, label)| {
                Button::new(label)
                    .label(label)
                    .h(px(29.))
                    .selected(self.section == section)
                    .toggled(self.section == section)
                    .on_click(cx.listener(move |view, _, _, cx| {
                        if let Some(Editor::Environment { settings, .. }) = &mut view.editor {
                            settings.section = section;
                        }
                        cx.notify();
                    }))
            }),
        )
    }

    pub fn fields(&self, busy: bool, cx: &mut Context<Workspace>) -> impl IntoElement {
        let palette = crate::theme::Palette::get(cx);
        let mut fields = div().v_flex().gap_4();
        for (key, label, _) in TOGGLES
            .iter()
            .copied()
            .filter(|(_, _, section)| *section == self.section)
        {
            fields = fields.child(
                Checkbox::new(key)
                    .label(label)
                    .checked(self.toggles[key])
                    .disabled(busy)
                    .on_click(cx.listener(move |view, checked: &bool, _, cx| {
                        if let Some(Editor::Environment { settings, .. }) = &mut view.editor {
                            settings.toggles.insert(key, *checked);
                            view.editor_dirty = true;
                        }
                        cx.notify();
                    })),
            );
        }
        for field in TEXT_FIELDS
            .iter()
            .filter(|field| field.section == self.section)
        {
            let state = &self.text[field.key];
            let mut row = div()
                .v_flex()
                .gap_2()
                .child(div().text_size(px(12.)).child(field.label));
            if let Some(state) = state.as_textarea() {
                fields = fields
                    .child(row.child(Textarea::new(state).aria_label(field.label).disabled(busy)));
                continue;
            }
            let Some(state) = state.as_input() else {
                continue;
            };
            if let Kind::Choice(choices) = field.kind {
                let state = state.clone();
                let view = cx.weak_entity();
                row = row.child(
                    Button::new(field.key)
                        .accessibility_label(format!("{}: {}", field.label, state.read(cx).value()))
                        .label(state.read(cx).value())
                        .icon(gpui_component::Icon::default().path("icons/chevron-down.svg"))
                        .justify_between()
                        .border_1()
                        .border_color(palette.line)
                        .rounded_md()
                        .disabled(busy)
                        .dropdown_menu(move |mut menu, _, _| {
                            for choice in choices {
                                let state = state.clone();
                                let view = view.clone();
                                menu = menu.item(PopupMenuItem::new(*choice).on_click(
                                    move |_, window, cx| {
                                        state.update(cx, |state, cx| {
                                            state.set_value(*choice, window, cx)
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
                row = row.child(
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
            fields = fields.child(row);
        }
        fields
    }
}
