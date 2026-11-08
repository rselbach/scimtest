use std::collections::BTreeSet;

use rune::{El, TextEdit, col, row};
use rune_kit::{Button, ButtonVariant, Checkbox};

use crate::{
    theme::Ui,
    workspace::{
        Editor, Workspace,
        editor::{field, two_columns},
        view::{Choice, dropdown, font_text},
    },
};

pub(crate) struct Form {
    pub kind: &'static str,
    fields: [TextEdit; 4],
    pub user: String,
    pub added: BTreeSet<String>,
    pub removed: BTreeSet<String>,
}

fn lifecycle_field(s: &mut Workspace, index: usize) -> &mut TextEdit {
    match &mut s.editor {
        Some(Editor::Lifecycle(form)) => &mut form.fields[index],
        _ => &mut s.scratch,
    }
}

fn user_label(user: &scimtest_core::model::User) -> String {
    format!(
        "{} {} ({}){}",
        user.fields.given_name,
        user.fields.family_name,
        user.fields.email,
        if user.fields.active {
            ""
        } else {
            " · inactive"
        }
    )
}

impl Form {
    pub fn new(kind: &'static str, user: String) -> Self {
        let mut fields: [TextEdit; 4] = std::array::from_fn(|_| TextEdit::new(""));
        fields[0].focused = kind == "joiner";
        Self {
            kind,
            fields,
            user,
            added: BTreeSet::new(),
            removed: BTreeSet::new(),
        }
    }

    pub fn values(&self) -> [String; 4] {
        self.fields.each_ref().map(|field| field.text.clone())
    }

    pub fn fields(&self, view: &Workspace, ui: &Ui, layer: &mut Vec<El>) -> El {
        let p = ui.p;
        let k = &ui.k;
        let mut kinds = row().key("lifecycle-kinds").gap(8.0);
        for (kind, label) in [
            ("joiner", "Joiner"),
            ("mover", "Mover"),
            ("leaver", "Leaver"),
        ] {
            let selected = self.kind == kind;
            kinds = kinds.child(
                Button::new(label)
                    .variant(if selected {
                        ButtonVariant::Contrast
                    } else {
                        ButtonVariant::Outline
                    })
                    .disabled(view.busy)
                    .on_press(move |s: &mut Workspace| s.edit_lifecycle(kind))
                    .build(k)
                    .key(kind)
                    .checked(selected),
            );
        }
        let mut body = col()
            .key("lifecycle-form")
            .w_full()
            .gap(16.0)
            .child(kinds)
            .child(
                font_text(
                    match self.kind {
                        "joiner" => {
                            "Create an active user, add group memberships, and provision through SCIM."
                        }
                        "mover" => {
                            "Change group memberships, push the changed groups, and check the next OIDC and SAML group claims."
                        }
                        _ => {
                            "Deactivate a user, end their sessions, send logout messages, revoke their tokens, and push active=false through SCIM."
                        }
                    },
                    13.0,
                    400.0,
                    p.muted,
                    ui,
                )
                .w_full()
                .wrap(),
            );
        if self.kind == "joiner" {
            let input = |index: usize, label: &'static str| {
                field(
                    format!("lifecycle-field-{index}"),
                    label,
                    "",
                    "",
                    &self.fields[index],
                    move |s: &mut Workspace| lifecycle_field(s, index),
                    ui,
                )
            };
            body = body
                .child(two_columns(input(0, "Given name"), input(1, "Family name")))
                .child(input(2, "Email"))
                .child(input(3, "Username (optional)"));
        } else {
            let users = view
                .directory()
                .map(|directory| {
                    directory
                        .projected_users()
                        .into_iter()
                        .filter(|user| {
                            !user.deleted && (self.kind == "leaver" || user.fields.active)
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let label = users
                .iter()
                .find(|user| user.id == self.user)
                .map(user_label)
                .unwrap_or_else(|| "Choose a user".into());
            let choices = users
                .iter()
                .map(|user| {
                    let id = user.id.clone();
                    Choice::new(user_label(user), move |s: &mut Workspace| {
                        if let Some(Editor::Lifecycle(form)) = &mut s.editor {
                            form.user = id.clone();
                            form.added.clear();
                            form.removed.clear();
                            s.editor_dirty = true;
                        }
                    })
                    .checked(user.id == self.user)
                })
                .collect();
            body = body.child(
                dropdown(
                    view,
                    "lifecycle-user",
                    label.clone(),
                    None,
                    view.busy,
                    choices,
                    ui,
                    layer,
                )
                .label(format!("User: {label}")),
            );
        }
        if self.kind == "leaver" {
            return body;
        }
        let Some(directory) = view.directory() else {
            return body;
        };
        let mut additions = col()
            .key("lifecycle-group-additions")
            .role("group")
            .label("Add to groups")
            .grow(1.0)
            .min_w(0.0)
            .gap(8.0)
            .child(font_text("Add to groups", 13.0, 400.0, p.text, ui).a11y_hidden());
        let mut removals = col()
            .key("lifecycle-group-removals")
            .role("group")
            .label("Remove from groups")
            .grow(1.0)
            .min_w(0.0)
            .gap(8.0)
            .child(font_text("Remove from groups", 13.0, 400.0, p.text, ui).a11y_hidden());
        let mut counts = [0, 0];
        for group in directory
            .projected_groups()
            .into_iter()
            .filter(|group| !group.deleted)
        {
            let member = self.kind == "mover" && group.fields.member_ids.contains(&self.user);
            let selected = if member { &self.removed } else { &self.added };
            let id = group.id;
            let checkbox = Checkbox::new(selected.contains(&id))
                .label(group.fields.display_name)
                .disabled(view.busy)
                .on_toggle({
                    let id = id.clone();
                    move |s: &mut Workspace| {
                        if let Some(Editor::Lifecycle(form)) = &mut s.editor {
                            let selected = if member {
                                &mut form.removed
                            } else {
                                &mut form.added
                            };
                            if !selected.remove(&id) {
                                selected.insert(id.clone());
                            }
                            s.editor_dirty = true;
                        }
                    }
                })
                .build(k)
                .key(format!("lifecycle-group-{id}"));
            if member {
                removals = removals.child(checkbox);
                counts[1] += 1;
            } else {
                additions = additions.child(checkbox);
                counts[0] += 1;
            }
        }
        if counts[0] == 0 {
            additions = additions.child(font_text("No groups available", 13.0, 400.0, p.muted, ui));
        }
        if counts[1] == 0 {
            removals = removals.child(font_text(
                "No current memberships",
                13.0,
                400.0,
                p.muted,
                ui,
            ));
        }
        let mut groups = row()
            .key("lifecycle-groups")
            .w_full()
            .items_start()
            .gap(16.0)
            .child(additions);
        if self.kind == "mover" {
            groups = groups.child(removals);
        }
        body.child(groups)
    }
}
