use std::collections::BTreeSet;

use rune::{El, TextEdit, col, row};
use rune_kit::Checkbox;
use scimtest_core::{Error, oidc::Faults};

use super::{
    Editor, Workspace,
    editor::field,
    view::{Choice, dropdown, font_text},
};
use crate::theme::{SEMIBOLD, Ui};

const TAMPER: &[(&str, &str, &str)] = &[
    ("wrong_issuer", "Wrong issuer", "both"),
    ("wrong_audience", "Wrong audience", "both"),
    ("unknown_kid", "Unknown signing key ID", "oidc"),
    ("alg_none", "Unsigned ID token (alg none)", "oidc"),
    ("nonce_mismatch", "Nonce mismatch", "oidc"),
    ("wrong_destination", "Wrong destination", "saml"),
    ("wrong_recipient", "Wrong recipient", "saml"),
    ("in_response_to_mismatch", "InResponseTo mismatch", "saml"),
    ("replayed_assertion", "Replayed assertion ID", "saml"),
    (
        "xsw_assertion",
        "Signature wrapping (signed assertion)",
        "saml",
    ),
    (
        "xsw_response",
        "Signature wrapping (signed response)",
        "saml",
    ),
    ("nameid_comment", "NameID comment injection", "saml"),
    (
        "logout_alg_none",
        "Logout token: unsigned (alg none)",
        "oidc",
    ),
    (
        "logout_wrong_audience",
        "Logout token: wrong audience",
        "oidc",
    ),
    (
        "logout_missing_events",
        "Logout token: missing events",
        "oidc",
    ),
    ("logout_repeated_jti", "Logout token: repeated jti", "oidc"),
];

pub(super) struct Form {
    fields: [TextEdit; 5],
    break_signature: bool,
    status: &'static str,
    tamper: BTreeSet<String>,
    oidc: bool,
    saml: bool,
}

fn fault_field(s: &mut Workspace, index: usize) -> &mut TextEdit {
    match &mut s.editor {
        Some(Editor::Faults(form)) => &mut form.fields[index],
        _ => &mut s.scratch,
    }
}

fn status_label(status: &str) -> &str {
    if status.is_empty() { "Success" } else { status }
}

impl Form {
    pub fn values(&self) -> Result<Faults, Error> {
        let values = self.fields.each_ref().map(|field| field.text.clone());
        let faults = Faults {
            id_token_ttl: Some(values[0].clone()),
            assertion_ttl: Some(values[1].clone()),
            clock_skew: Some(values[2].clone()),
            drop_claims: vec![values[3].clone()],
            token_error: values[4].clone(),
            break_signature: self.break_signature,
            saml_status: self.status.into(),
            tamper: self.tamper.iter().cloned().collect(),
        }
        .normalized()?;
        if !faults.active() {
            return Err(Error::Validation("Choose at least one fault".into()));
        }
        Ok(faults)
    }

    pub fn fields(&self, workspace: &Workspace, ui: &Ui, layer: &mut Vec<El>) -> El {
        let p = ui.p;
        let busy = workspace.busy;
        let input = |index: usize, label: &'static str| {
            field(
                format!("fault-field-{index}"),
                label,
                "",
                "",
                &self.fields[index],
                move |s: &mut Workspace| fault_field(s, index),
                ui,
            )
        };
        let mut body = col().key("faults-form").w_full().gap(16.0).child(
            font_text(
                "Arms the next matching flow. Logout faults wait for a back-channel logout. Leave durations empty to keep the normal lifetime; 0s explicitly expires immediately.",
                13.0,
                400.0,
                p.muted,
                ui,
            )
            .w_full()
            .wrap(),
        );
        let mut lifetimes = row().w_full().gap(16.0).items_start();
        if self.oidc {
            lifetimes = lifetimes.child(input(0, "ID token lifetime (e.g. -1m)"));
        }
        if self.saml {
            lifetimes = lifetimes.child(input(1, "Assertion lifetime (e.g. -1m)"));
        }
        body = body
            .child(lifetimes)
            .child(input(2, "Clock skew (e.g. 5m or -1h)"))
            .child(
                Checkbox::new(self.break_signature)
                    .label("Break signatures")
                    .disabled(busy)
                    .on_toggle(|s: &mut Workspace| {
                        if let Some(Editor::Faults(form)) = &mut s.editor {
                            form.break_signature = !form.break_signature;
                            s.editor_dirty = true;
                        }
                    })
                    .build(&ui.k)
                    .key("fault-break-signature"),
            )
            .child(input(3, "OIDC claims to remove (comma separated)"));
        if self.oidc {
            body = body.child(input(
                4,
                "Token endpoint error (e.g. temporarily_unavailable)",
            ));
        }
        if self.saml {
            let status = status_label(self.status);
            let choices = ["", "Responder", "AuthnFailed"]
                .into_iter()
                .map(|choice| {
                    Choice::new(status_label(choice), move |s: &mut Workspace| {
                        if let Some(Editor::Faults(form)) = &mut s.editor {
                            form.status = choice;
                            s.editor_dirty = true;
                        }
                    })
                    .checked(choice == self.status)
                })
                .collect();
            body = body.child(
                row()
                    .gap(12.0)
                    .center_y()
                    .child(font_text("SAML status", 13.0, 400.0, p.text, ui).a11y_hidden())
                    .child(
                        dropdown(
                            workspace,
                            "fault-saml-status",
                            status,
                            Some(160.0),
                            busy,
                            choices,
                            ui,
                            layer,
                        )
                        .label(format!("SAML status: {status}")),
                    ),
            );
        }
        body = body.child(font_text(
            "Tamper with validation",
            13.0,
            SEMIBOLD,
            p.text,
            ui,
        ));
        for &(id, label, protocol) in TAMPER {
            if protocol == "oidc" && !self.oidc || protocol == "saml" && !self.saml {
                continue;
            }
            body = body.child(
                Checkbox::new(self.tamper.contains(id))
                    .label(label)
                    .disabled(busy)
                    .on_toggle(move |s: &mut Workspace| {
                        if let Some(Editor::Faults(form)) = &mut s.editor {
                            if !form.tamper.remove(id) {
                                form.tamper.insert(id.into());
                            }
                            s.editor_dirty = true;
                        }
                    })
                    .build(&ui.k)
                    .key(id),
            );
        }
        body
    }
}

impl Workspace {
    pub(super) fn edit_faults(&mut self) {
        let Some(directory) = self.directory() else {
            return;
        };
        let oidc = directory.environment.settings.supports_oidc();
        let saml = directory.environment.settings.supports_saml();
        let faults = &self.resilience.manual;
        let mut fields = [
            faults.id_token_ttl.clone().unwrap_or_default(),
            faults.assertion_ttl.clone().unwrap_or_default(),
            faults.clock_skew.clone().unwrap_or_default(),
            faults.drop_claims.join(", "),
            faults.token_error.clone(),
        ]
        .map(|value| TextEdit::new(&value));
        let first = match (oidc, saml) {
            (true, _) => 0,
            (_, true) => 1,
            _ => 2,
        };
        fields[first].focused = true;
        let form = Form {
            fields,
            oidc,
            saml,
            break_signature: faults.break_signature,
            status: match faults.saml_status.as_str() {
                "Responder" => "Responder",
                "AuthnFailed" => "AuthnFailed",
                _ => "",
            },
            tamper: faults.tamper.iter().cloned().collect(),
        };
        self.open_editor(Editor::Faults(form));
        self.failed = false;
    }
}
