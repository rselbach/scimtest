use super::{Editor, Workspace};
use gpui::{Context, Focusable, Window};
use gpui_component::input::{AnyInputState, InputEvent};

impl Workspace {
    pub(super) fn update_focus(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let account_visible = self.account_locked() || self.account_open;
        if account_visible != self.account_visible {
            if account_visible {
                self.account_return_focus = window.focused(cx);
                window.focus(&self.account_focus, cx);
            } else {
                let focus = self
                    .account_return_focus
                    .take()
                    .unwrap_or_else(|| self.focus.clone());
                window.focus(&focus, cx);
            }
        }
        if account_visible || self.account_visible {
            let focus = window.focused(cx);
            let view = cx.weak_entity();
            window.on_next_frame(move |window, cx| {
                let _ = view.update(cx, |view, cx| {
                    let scope = if view.account_locked() || view.account_open {
                        &view.account_focus
                    } else {
                        &view.focus
                    };
                    if window.focused(cx) == focus && !scope.contains_focused(window, cx) {
                        window.focus(scope, cx);
                    }
                });
            });
        }
        self.account_visible = account_visible;
        if account_visible {
            return;
        }
        let inputs = self.editor.as_ref().map(Editor::inputs).unwrap_or_default();
        let kind = self
            .editor
            .as_ref()
            .map(|editor| (std::mem::discriminant(editor), inputs.first().cloned()));
        if kind != self.editor_kind {
            self.editor_dirty = false;
            self.discard_return_focus = None;
            self.editor_subscriptions.clear();
            for input in inputs {
                let subscription = match input {
                    AnyInputState::Input(input) => {
                        cx.subscribe(&input, |view, _, event: &InputEvent, cx| {
                            if matches!(event, InputEvent::Change) {
                                view.editor_dirty = true;
                                cx.notify();
                            }
                        })
                    }
                    AnyInputState::Textarea(input) => {
                        cx.subscribe(&input, |view, _, event: &InputEvent, cx| {
                            if matches!(event, InputEvent::Change) {
                                view.editor_dirty = true;
                                cx.notify();
                            }
                        })
                    }
                    _ => continue,
                };
                self.editor_subscriptions.push(subscription);
            }
            if let Some(editor) = &self.editor {
                if self.editor_kind.is_none() {
                    self.return_focus = self.previous_focus.clone();
                }
                let focus = match editor {
                    Editor::User { fields, .. } => fields[3].focus_handle(cx),
                    Editor::Group { name, .. } | Editor::Environment { name, .. } => {
                        name.focus_handle(cx)
                    }
                    Editor::Tools { count, .. } => count.focus_handle(cx),
                    Editor::Idp { base_url, .. } => base_url.focus_handle(cx),
                    _ => self.editor_focus.clone(),
                };
                window.focus(&focus, cx);
            } else {
                let focus = self
                    .return_focus
                    .take()
                    .unwrap_or_else(|| self.focus.clone());
                window.focus(&focus, cx);
            }
            self.editor_kind = kind;
        }
        if self.editor.is_none() {
            self.previous_focus = window.focused(cx);
        }
    }
}

impl Editor {
    fn inputs(&self) -> Vec<AnyInputState> {
        match self {
            Self::User {
                fields, attributes, ..
            } => fields
                .iter()
                .cloned()
                .map(AnyInputState::Input)
                .chain(std::iter::once(AnyInputState::Textarea(attributes.clone())))
                .collect(),
            Self::Group { name, .. } => vec![AnyInputState::Input(name.clone())],
            Self::Environment {
                name,
                slug,
                settings,
                ..
            } => [name, slug]
                .into_iter()
                .cloned()
                .map(AnyInputState::Input)
                .chain(settings.inputs())
                .collect(),
            Self::Tools { count, domain } => [count, domain]
                .into_iter()
                .cloned()
                .map(AnyInputState::Input)
                .collect(),
            Self::Idp { base_url, .. } => vec![AnyInputState::Input(base_url.clone())],
            Self::Faults(form) => form.inputs(),
            Self::Lifecycle(form) => form.inputs(),
            _ => Vec::new(),
        }
    }
}
