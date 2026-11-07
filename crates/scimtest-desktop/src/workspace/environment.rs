use std::collections::{BTreeMap, BTreeSet};

use rune::{El, TextEdit, Tx, col, el, row};
use rune_kit::{
    Button, ButtonVariant, Checkbox, IconButton, IconButtonVariant, Switch, TextArea, TextInput,
};
use scimtest_core::{Error, configuration::SettingsPatch, model::Environment};
use serde_json::{Value, json};

use super::{
    Editor, Workspace,
    editor::two_columns,
    view::{Choice, caption, dropdown, font_text},
};
use crate::{
    icons,
    theme::{SEMIBOLD, Ui},
};

#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum Section {
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

pub(crate) struct EnvironmentForm {
    pub(super) section: Section,
    text: BTreeMap<&'static str, TextEdit>,
    pub(super) toggles: BTreeMap<&'static str, bool>,
    /// Secret fields showing their value.
    revealed: BTreeSet<&'static str>,
}

/// The open environment editor's settings form.
fn form(s: &mut Workspace) -> Option<&mut EnvironmentForm> {
    match &mut s.editor {
        Some(Editor::Environment { settings, .. }) => Some(settings),
        _ => None,
    }
}

fn setting<'a>(s: &'a mut Workspace, key: &'static str) -> &'a mut TextEdit {
    match &mut s.editor {
        Some(Editor::Environment { settings, .. }) => match settings.text.get_mut(key) {
            Some(edit) => edit,
            None => &mut s.scratch,
        },
        _ => &mut s.scratch,
    }
}

fn environment_name(s: &mut Workspace) -> &mut TextEdit {
    match &mut s.editor {
        Some(Editor::Environment { name, .. }) => name,
        _ => &mut s.scratch,
    }
}

fn environment_slug(s: &mut Workspace) -> &mut TextEdit {
    match &mut s.editor {
        Some(Editor::Environment { slug, .. }) => slug,
        _ => &mut s.scratch,
    }
}

fn flip(s: &mut Workspace, key: &'static str) {
    if let Some(settings) = form(s) {
        let on = settings.toggle(key);
        settings.toggles.insert(key, !on);
        s.editor_dirty = true;
    }
}

impl EnvironmentForm {
    pub fn new(environment: Option<&Environment>) -> Result<Self, Error> {
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
            let edit = TextEdit::new(value);
            let edit = match field.kind {
                Kind::Secret => edit.secure(),
                _ => edit,
            };
            text.insert(field.key, edit);
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
            revealed: BTreeSet::new(),
        })
    }

    pub fn patch(&self) -> Result<SettingsPatch, Error> {
        let mut values = json!({});
        for (key, enabled) in &self.toggles {
            values[*key] = json!(enabled);
        }
        for field in TEXT_FIELDS {
            let value = self.value(field.key);
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
        name: &TextEdit,
        slug: &TextEdit,
        id: Option<&str>,
        ui: &Ui,
        layer: &mut Vec<El>,
    ) -> El {
        let body = col()
            .key("environment-form")
            .w_full()
            .gap(20.0)
            .child(self.steps(ui));
        match self.section {
            Section::General => body.child(self.general(workspace, name, slug, ui, layer)),
            Section::Oidc => body.child(self.oidc(workspace, ui, layer)),
            Section::Saml => body.child(self.saml(workspace, ui, layer)),
            Section::Scim => body.child(self.scim(workspace, id.is_some(), ui, layer)),
            Section::Review => body.child(self.review(workspace, name, slug, id, ui)),
        }
    }

    /// Previous and next buttons for moving through the wizard.
    pub fn nav(&self, _workspace: &Workspace, ui: &Ui) -> El {
        let index = self.section.index();
        let last = Section::STEPS.len() - 1;
        let mut nav = row().key("wizard-nav").gap(8.0).center_y();
        if index > 0 {
            nav = nav.child(
                Button::new("Previous")
                    .variant(ButtonVariant::Outline)
                    .on_press(move |s: &mut Workspace| s.set_environment_step(index - 1))
                    .build(&ui.k)
                    .key("wizard-previous"),
            );
        }
        if index < last {
            nav = nav.child(
                Button::new("Next")
                    .variant(ButtonVariant::Contrast)
                    .on_press(move |s: &mut Workspace| s.set_environment_step(index + 1))
                    .build(&ui.k)
                    .key("wizard-next"),
            );
        }
        nav
    }

    fn steps(&self, ui: &Ui) -> El {
        let mut bar = row()
            .key("wizard-steps")
            .w_full()
            .flex_wrap()
            .gap(4.0)
            .padding(4.0)
            .radius(6.0)
            .fill(ui.p.soft);
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
                Button::new(text)
                    .variant(if current {
                        ButtonVariant::Neutral
                    } else {
                        ButtonVariant::Ghost
                    })
                    .on_press(move |s: &mut Workspace| s.set_environment_step(index))
                    .build(&ui.k)
                    .key(format!("step-{index}"))
                    .label(format!("Step {}: {label}", index + 1))
                    .checked(current),
            );
        }
        bar
    }

    fn general(
        &self,
        workspace: &Workspace,
        name: &TextEdit,
        slug: &TextEdit,
        ui: &Ui,
        layer: &mut Vec<El>,
    ) -> El {
        col()
            .key("environment-general")
            .w_full()
            .gap(16.0)
            .child(section_title(
                "Environment",
                "Name this test environment and choose the shared sign-in behavior.",
                ui,
            ))
            .child(two_columns(
                plain_input(
                    "environment-name",
                    "Environment name",
                    "Use the name of the app or integration you are testing.",
                    "Greendale Portal",
                    name,
                    environment_name,
                    ui,
                ),
                plain_input(
                    "environment-slug",
                    "Endpoint name",
                    "Generated from the name and used in OIDC and SAML URLs.",
                    "Generated from the name",
                    slug,
                    environment_slug,
                    ui,
                ),
            ))
            .child(self.field_pair(workspace, "chooser_mode", "persona", ui, layer))
            .child(two_columns(
                self.field(workspace, "groups_overage_threshold", ui, layer),
                el().grow(1.0).min_w(0.0),
            ))
            .child(self.toggle_row(
                "include_groups_claim",
                "Include groups in OIDC claims and SAML attributes",
                workspace.busy,
                ui,
            ))
    }

    fn oidc(&self, workspace: &Workspace, ui: &Ui, layer: &mut Vec<El>) -> El {
        let busy = workspace.busy;
        let mut content = col()
            .key("environment-oidc")
            .w_full()
            .gap(16.0)
            .child(self.section_header(
                "OIDC",
                "Sign users in to your app with OpenID Connect.",
                "oidc_enabled",
                busy,
                ui,
            ))
            .child(self.field(workspace, "oidc_client_id", ui, layer))
            .child(self.field(workspace, "oidc_client_secret", ui, layer))
            .child(self.toggle_row(
                "oidc_public_client",
                "Public client (no client secret)",
                busy,
                ui,
            ))
            .child(self.field(workspace, "oidc_redirect_uris", ui, layer))
            .child(self.toggle_row(
                "allow_any_oidc_redirect",
                "Allow arbitrary redirect URIs",
                busy,
                ui,
            ))
            .child(self.field(workspace, "oidc_backchannel_logout_uri", ui, layer))
            .child(self.toggle_row(
                "oidc_backchannel_logout_session_required",
                "Require a session ID for back-channel logout",
                busy,
                ui,
            ))
            .child(self.field(workspace, "oidc_access_token_audience", ui, layer))
            .child(self.toggle_row(
                "oidc_jwt_access_tokens",
                "Issue JWT access tokens",
                busy,
                ui,
            ))
            .child(self.toggle_row(
                "regenerate_oidc_secret",
                "Generate a new client secret when saving",
                busy,
                ui,
            ))
            .child(workspace.disclosure("oidc-claims", "Claim mappings", ui));
        if workspace.disclosures.contains("oidc-claims") {
            content = content.child(
                col()
                    .key("oidc-claims-fields")
                    .w_full()
                    .gap(16.0)
                    .pl(12.0)
                    .child(self.field_pair(
                        workspace,
                        "oidc_claim_mappings.name",
                        "oidc_claim_mappings.given_name",
                        ui,
                        layer,
                    ))
                    .child(self.field_pair(
                        workspace,
                        "oidc_claim_mappings.family_name",
                        "oidc_claim_mappings.username",
                        ui,
                        layer,
                    ))
                    .child(self.field_pair(
                        workspace,
                        "oidc_claim_mappings.email",
                        "oidc_claim_mappings.groups",
                        ui,
                        layer,
                    )),
            );
        }
        content
    }

    fn saml(&self, workspace: &Workspace, ui: &Ui, layer: &mut Vec<El>) -> El {
        let mut content = col()
            .key("environment-saml")
            .w_full()
            .gap(16.0)
            .child(self.section_header(
                "SAML",
                "Configure scimtest as the identity provider for your service provider.",
                "saml_enabled",
                workspace.busy,
                ui,
            ))
            .child(self.field_pair(workspace, "saml_entity_id", "saml_acs_url", ui, layer))
            .child(self.field_pair(workspace, "saml_slo_url", "saml_audience", ui, layer))
            .child(self.field(workspace, "saml_name_id_field", ui, layer))
            .child(self.field(workspace, "saml_attribute_mappings.email", ui, layer))
            .child(workspace.disclosure("saml-signing", "Signing and Encryption", ui));
        if workspace.disclosures.contains("saml-signing") {
            content = content.child(
                col()
                    .key("saml-signing-fields")
                    .w_full()
                    .gap(16.0)
                    .pl(12.0)
                    .child(self.field(workspace, "saml_signing_mode", ui, layer))
                    .child(self.field(workspace, "saml_request_certificate_pem", ui, layer))
                    .child(self.field(workspace, "saml_encryption_certificate_pem", ui, layer))
                    .child(self.field(workspace, "saml_encryption_algorithm", ui, layer)),
            );
        }
        content =
            content.child(workspace.disclosure("saml-mappings", "SAML attribute mappings", ui));
        if workspace.disclosures.contains("saml-mappings") {
            content = content.child(
                col()
                    .key("saml-mappings-fields")
                    .w_full()
                    .gap(16.0)
                    .pl(12.0)
                    .child(self.field_pair(
                        workspace,
                        "saml_attribute_mappings.given_name",
                        "saml_attribute_mappings.family_name",
                        ui,
                        layer,
                    ))
                    .child(self.field_pair(
                        workspace,
                        "saml_attribute_mappings.username",
                        "saml_attribute_mappings.groups",
                        ui,
                        layer,
                    )),
            );
        }
        content
    }

    fn scim(&self, workspace: &Workspace, editing: bool, ui: &Ui, layer: &mut Vec<El>) -> El {
        let busy = workspace.busy;
        col()
            .key("environment-scim")
            .w_full()
            .gap(16.0)
            .child(self.section_header(
                "SCIM",
                "Provision this environment's users and groups to your app.",
                "scim_enabled",
                busy,
                ui,
            ))
            .child(self.field(workspace, "scim_base_url", ui, layer))
            .child(self.field(workspace, "scim_bearer_token", ui, layer))
            .child(
                Button::new("Test connection")
                    .variant(ButtonVariant::Outline)
                    .disabled(busy || !editing)
                    .on_press(|s: &mut Workspace| s.scim_action("test", None))
                    .build(&ui.k)
                    .key("test-scim-connection")
                    .w_full(),
            )
            .child(self.toggle_row(
                "scim_auto_open_trace",
                "Auto-open after sync and import",
                busy,
                ui,
            ))
    }

    fn review(
        &self,
        workspace: &Workspace,
        name: &TextEdit,
        slug: &TextEdit,
        id: Option<&str>,
        ui: &Ui,
    ) -> El {
        let p = ui.p;
        let mut tiles = row().key("review-integrations").w_full().gap(12.0);
        for (label, key) in [
            ("OIDC", "oidc_enabled"),
            ("SAML", "saml_enabled"),
            ("SCIM", "scim_enabled"),
        ] {
            let enabled = self.toggle(key);
            let state = if enabled { "Enabled" } else { "Disabled" };
            tiles = tiles.child(
                col()
                    .key(format!("review-{key}"))
                    .role("group")
                    .label(format!("{label}: {state}"))
                    .grow(1.0)
                    .min_w(0.0)
                    .gap(4.0)
                    .padding(12.0)
                    .radius(6.0)
                    .border(1.0, p.line)
                    .child(
                        row()
                            .w_full()
                            .justify_between()
                            .child(font_text(label, 13.0, SEMIBOLD, p.text, ui))
                            .child(font_text(
                                state,
                                12.0,
                                400.0,
                                if enabled { p.success } else { p.muted },
                                ui,
                            )),
                    )
                    .child(font_text(
                        if enabled { "Included" } else { "Not included" },
                        12.0,
                        400.0,
                        p.muted,
                        ui,
                    )),
            );
        }
        let mut content = col()
            .key("environment-review")
            .w_full()
            .gap(16.0)
            .child(section_title(
                "Review environment",
                "Confirm the environment and integrations before saving.",
                ui,
            ))
            .child(
                row()
                    .w_full()
                    .gap(12.0)
                    .child(review_value(
                        "review-name",
                        "Environment name",
                        &name.text,
                        ui,
                    ))
                    .child(review_value(
                        "review-slug",
                        "Endpoint name",
                        &slug.text,
                        ui,
                    )),
            )
            .child(tiles)
            .child(
                font_text(
                    "Select an integration to make corrections, or save the environment to apply these settings.",
                    12.0,
                    400.0,
                    p.muted,
                    ui,
                )
                .w_full()
                .wrap(),
            );
        let Some(id) = id else {
            return content;
        };
        let export = |key: &'static str, label: &'static str, save: bool| {
            let id = id.to_owned();
            Button::new(label)
                .variant(ButtonVariant::Outline)
                .disabled(workspace.busy)
                .on_press_tx(move |s: &mut Workspace, tx: &mut Tx| {
                    s.export_connection(id.clone(), save, tx)
                })
                .build(&ui.k)
                .key(key)
        };
        content = content.child(
            row()
                .key("connection-export")
                .gap(8.0)
                .child(export("copy-connection", "Copy config JSON", false))
                .child(export("save-connection", "Save config JSON…", true)),
        );
        content
    }

    fn section_header(
        &self,
        title: &'static str,
        description: &'static str,
        key: &'static str,
        busy: bool,
        ui: &Ui,
    ) -> El {
        let enabled = self.toggle(key);
        row()
            .w_full()
            .items_start()
            .gap(16.0)
            .child(section_title(title, description, ui))
            .child(
                row()
                    .gap(8.0)
                    .center_y()
                    .child(
                        caption(if enabled { "Enabled" } else { "Disabled" }, ui)
                            .key(format!("{key}-state"))
                            .a11y_hidden(),
                    )
                    .child(
                        Switch::new(enabled)
                            .label(format!("{title} enabled"))
                            .hide_label()
                            .disabled(busy)
                            .on_toggle(move |s: &mut Workspace| flip(s, key))
                            .build(&ui.k)
                            .key(format!("{key}-switch")),
                    ),
            )
    }

    /// The problem with `section`, if it is in use and a required value is blank.
    pub fn section_error(&self, name: &TextEdit, section: Section) -> Option<String> {
        if section == Section::General && name.text.trim().is_empty() {
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
            .filter(|(_, key)| self.value(key).trim().is_empty())
            .map(|(label, _)| *label)
            .collect::<Vec<_>>();
        (!missing.is_empty()).then(|| format!("{label} needs {}.", missing.join(", ")))
    }

    /// The first section, in wizard order, with a problem.
    pub fn first_error(&self, name: &TextEdit) -> Option<(Section, String)> {
        [
            Section::General,
            Section::Oidc,
            Section::Saml,
            Section::Scim,
        ]
        .into_iter()
        .find_map(|section| {
            self.section_error(name, section)
                .map(|message| (section, message))
        })
    }

    fn value(&self, key: &str) -> &str {
        self.text.get(key).map_or("", |edit| edit.text.as_str())
    }

    fn toggle(&self, key: &str) -> bool {
        self.toggles.get(key).copied().unwrap_or(false)
    }

    fn toggle_row(&self, key: &'static str, label: &'static str, busy: bool, ui: &Ui) -> El {
        let help = toggle_hint(key);
        let checkbox = Checkbox::new(self.toggle(key))
            .label(label)
            .disabled(busy)
            .on_toggle(move |s: &mut Workspace| flip(s, key))
            .build(&ui.k)
            .key(key);
        if help.is_empty() {
            return checkbox;
        }
        col()
            .w_full()
            .gap(4.0)
            .child(checkbox.description(help))
            .child(caption(help, ui).pl(28.0).w_full().wrap().a11y_hidden())
    }

    fn field_pair(
        &self,
        workspace: &Workspace,
        left: &'static str,
        right: &'static str,
        ui: &Ui,
        layer: &mut Vec<El>,
    ) -> El {
        two_columns(
            self.field(workspace, left, ui, layer),
            self.field(workspace, right, ui, layer),
        )
    }

    fn field(&self, workspace: &Workspace, key: &'static str, ui: &Ui, layer: &mut Vec<El>) -> El {
        let (Some(field), Some(edit)) = (
            TEXT_FIELDS.iter().find(|field| field.key == key),
            self.text.get(key),
        ) else {
            return el();
        };
        let busy = workspace.busy;
        let label = field.label;
        let control = match field.kind {
            Kind::Lines => TextArea::new(edit)
                .width(None)
                .label(label)
                .auto_grow(3, 6)
                .disabled(busy)
                .on_edit(move |s: &mut Workspace| setting(s, key))
                .on_change(|s: &mut Workspace, _: &mut Tx| s.editor_dirty = true)
                .build(&ui.k)
                .key("input"),
            Kind::Choice(choices) => {
                let current = edit.text.as_str();
                let shown = choices
                    .iter()
                    .find(|(value, _)| *value == current)
                    .map_or(current, |(_, label)| *label)
                    .to_owned();
                let options = choices
                    .iter()
                    .map(|&(value, choice)| {
                        Choice::new(choice, move |s: &mut Workspace| {
                            if let Some(settings) = form(s) {
                                settings.text.insert(key, TextEdit::new(value));
                                s.editor_dirty = true;
                            }
                        })
                        .checked(value == current)
                    })
                    .collect();
                dropdown(
                    workspace,
                    &format!("{key}-picker"),
                    shown.clone(),
                    None,
                    busy,
                    options,
                    ui,
                    layer,
                )
                .label(format!("{label}: {shown}"))
            }
            Kind::Secret => {
                let revealed = self.revealed.contains(key);
                TextInput::new(edit)
                    .width(None)
                    .label(label)
                    .secure()
                    .revealed(revealed)
                    .trailing(
                        IconButton::new(&icons::EYE)
                            .variant(IconButtonVariant::Ghost)
                            .label(if revealed {
                                format!("Hide {label}")
                            } else {
                                format!("Show {label}")
                            })
                            .on_press(move |s: &mut Workspace| {
                                if let Some(settings) = form(s)
                                    && !settings.revealed.remove(key)
                                {
                                    settings.revealed.insert(key);
                                }
                            })
                            .build(&ui.k)
                            .key("reveal")
                            .checked(revealed),
                    )
                    .disabled(busy)
                    .on_edit(move |s: &mut Workspace| setting(s, key))
                    .on_change(|s: &mut Workspace, _: &mut Tx| s.editor_dirty = true)
                    .build(&ui.k)
                    .key("input")
            }
            Kind::Text | Kind::Number => TextInput::new(edit)
                .width(None)
                .label(label)
                .disabled(busy)
                .on_edit(move |s: &mut Workspace| setting(s, key))
                .on_change(|s: &mut Workspace, _: &mut Tx| s.editor_dirty = true)
                .build(&ui.k)
                .key("input"),
        };
        let mut column = col()
            .key(key)
            .grow(1.0)
            .min_w(0.0)
            .gap(8.0)
            .child(font_text(label, 12.0, 400.0, ui.p.text, ui).a11y_hidden())
            .child(control);
        let help = hint(key);
        if !help.is_empty() {
            column = column.child(caption(help, ui).w_full().wrap());
        }
        column
    }
}

impl Workspace {
    /// Moves the wizard to `section` and explains why the change was blocked.
    pub(super) fn show_environment_error(&mut self, section: Section, message: String) {
        if let Some(settings) = form(self) {
            settings.section = section;
        }
        self.fail(message);
    }
}

fn section_title(title: &'static str, description: &'static str, ui: &Ui) -> El {
    col()
        .grow(1.0)
        .min_w(0.0)
        .gap(4.0)
        .child(font_text(title, 16.0, SEMIBOLD, ui.p.text, ui).role("heading"))
        .child(caption(description, ui).w_full().wrap())
}

/// A labeled input with help text, for the general step's name fields.
fn plain_input(
    key: &'static str,
    label: &'static str,
    help: &'static str,
    placeholder: &'static str,
    edit: &TextEdit,
    access: fn(&mut Workspace) -> &mut TextEdit,
    ui: &Ui,
) -> El {
    col()
        .key(key)
        .grow(1.0)
        .min_w(0.0)
        .gap(8.0)
        .child(font_text(label, 12.0, 400.0, ui.p.text, ui).a11y_hidden())
        .child(
            TextInput::new(edit)
                .width(None)
                .label(label)
                .placeholder(placeholder)
                .on_edit(access)
                .on_change(|s: &mut Workspace, _: &mut Tx| s.editor_dirty = true)
                .build(&ui.k)
                .key("input"),
        )
        .child(caption(help, ui).w_full().wrap())
}

fn review_value(key: &'static str, label: &'static str, value: &str, ui: &Ui) -> El {
    col()
        .key(key)
        .grow(1.0)
        .min_w(0.0)
        .gap(4.0)
        .padding(12.0)
        .radius(6.0)
        .border(1.0, ui.p.line)
        .child(caption(label, ui))
        .child(font_text(value, 13.0, SEMIBOLD, ui.p.text, ui).truncate())
}
