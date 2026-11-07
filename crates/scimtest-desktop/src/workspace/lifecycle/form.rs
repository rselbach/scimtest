use super::*;
use crate::dropdown::DropdownMenu;
use crate::workspace::{editor::field, input};
use gpui::{Entity, px};
use gpui_component::{Selectable, checkbox::Checkbox, input::InputState, menu::PopupMenuItem};

pub(in crate::workspace) struct Form {
    pub kind: &'static str,
    fields: [Entity<InputState>; 4],
    pub user: String,
    pub added: BTreeSet<String>,
    pub removed: BTreeSet<String>,
}
impl Form {
    pub fn inputs(&self) -> Vec<gpui_component::input::AnyInputState> {
        self.fields
            .iter()
            .cloned()
            .map(gpui_component::input::AnyInputState::Input)
            .collect()
    }

    pub fn new(
        kind: &'static str,
        user: String,
        window: &mut Window,
        cx: &mut Context<Workspace>,
    ) -> Self {
        Self {
            kind,
            fields: std::array::from_fn(|_| input("", "", window, cx)),
            user,
            added: BTreeSet::new(),
            removed: BTreeSet::new(),
        }
    }
    pub fn values(&self, cx: &Context<Workspace>) -> [String; 4] {
        self.fields
            .each_ref()
            .map(|field| field.read(cx).value().to_string())
    }
    pub fn fields(&self, view: &Workspace, cx: &mut Context<Workspace>) -> Div {
        let palette = Palette::get(cx);
        let mut body = div().v_flex().gap_4().child(
            div().h_flex().gap_2().children(
                [
                    ("joiner", "Joiner"),
                    ("mover", "Mover"),
                    ("leaver", "Leaver"),
                ]
                .into_iter()
                .map(|(kind, label)| {
                    Button::new(kind)
                        .label(label)
                        .selected(self.kind == kind)
                        .toggled(self.kind == kind)
                        .disabled(view.busy)
                        .on_click(cx.listener(move |view, _, window, cx| {
                            view.edit_lifecycle(kind, window, cx)
                        }))
                }),
            ),
        );
        body = body.child(div().text_color(palette.muted).whitespace_normal().child(match self.kind {
            "joiner" => "Create an active user, add group memberships, and provision through SCIM.",
            "mover" => "Change group memberships, push the changed groups, and check the next OIDC and SAML group claims.",
            _ => "Deactivate a user, end their sessions, send logout messages, revoke their tokens, and push active=false through SCIM.",
        }));
        if self.kind == "joiner" {
            body = body
                .child(
                    div()
                        .h_flex()
                        .gap_4()
                        .child(field("Given name", &self.fields[0]))
                        .child(field("Family name", &self.fields[1])),
                )
                .child(field("Email", &self.fields[2]))
                .child(field("Username (optional)", &self.fields[3]));
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
                .map(|user| {
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
                })
                .unwrap_or_else(|| "Choose a user".into());
            let target = cx.weak_entity();
            body = body.child(
                Button::new("lifecycle-user")
                    .accessibility_label(format!("User: {label}"))
                    .label(label)
                    .disabled(view.busy)
                    .dropdown_menu(move |mut menu, _, _| {
                        for user in &users {
                            let target = target.clone();
                            let id = user.id.clone();
                            menu = menu.item(
                                PopupMenuItem::new(format!(
                                    "{} {} ({}){}",
                                    user.fields.given_name,
                                    user.fields.family_name,
                                    user.fields.email,
                                    if user.fields.active {
                                        ""
                                    } else {
                                        " · inactive"
                                    }
                                ))
                                .on_click(move |_, _, cx| {
                                    let _ = target.update(cx, |view, cx| {
                                        if let Some(Editor::Lifecycle(form)) = &mut view.editor {
                                            form.user = id.clone();
                                            form.added.clear();
                                            form.removed.clear();
                                            view.editor_dirty = true;
                                        }
                                        cx.notify();
                                    });
                                }),
                            );
                        }
                        menu
                    }),
            );
        }
        if self.kind == "leaver" {
            return body;
        }
        let Some(directory) = view.directory() else {
            return body;
        };
        let mut additions = div()
            .id("lifecycle-group-additions")
            .role(gpui::Role::Group)
            .aria_label("Add to groups")
            .v_flex()
            .flex_1()
            .min_w_0()
            .gap_2()
            .child("Add to groups");
        let mut removals = div()
            .id("lifecycle-group-removals")
            .role(gpui::Role::Group)
            .aria_label("Remove from groups")
            .v_flex()
            .flex_1()
            .min_w_0()
            .gap_2()
            .child("Remove from groups");
        let mut counts = [0, 0];
        for group in directory
            .projected_groups()
            .into_iter()
            .filter(|group| !group.deleted)
        {
            let member = self.kind == "mover" && group.fields.member_ids.contains(&self.user);
            let selected = if member { &self.removed } else { &self.added };
            let id = group.id;
            let checkbox = Checkbox::new(SharedString::from(format!("lifecycle-group-{id}")))
                .label(group.fields.display_name)
                .checked(selected.contains(&id))
                .disabled(view.busy)
                .on_click(cx.listener(move |view, checked: &bool, _, cx| {
                    if let Some(Editor::Lifecycle(form)) = &mut view.editor {
                        let selected = if member {
                            &mut form.removed
                        } else {
                            &mut form.added
                        };
                        if *checked {
                            selected.insert(id.clone());
                        } else {
                            selected.remove(&id);
                        }
                        view.editor_dirty = true;
                    }
                    cx.notify();
                }));
            if member {
                removals = removals.child(checkbox);
                counts[1] += 1;
            } else {
                additions = additions.child(checkbox);
                counts[0] += 1;
            }
        }
        if counts[0] == 0 {
            additions =
                additions.child(div().text_color(palette.muted).child("No groups available"));
        }
        if counts[1] == 0 {
            removals = removals.child(
                div()
                    .text_color(palette.muted)
                    .child("No current memberships"),
            );
        }
        body.child(
            div()
                .h_flex()
                .items_start()
                .gap_4()
                .text_size(px(13.))
                .child(additions)
                .when(self.kind == "mover", |row| row.child(removals)),
        )
    }
}
