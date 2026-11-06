use super::Workspace;
use crate::theme::Palette;
use gpui::{Context, IntoElement, MouseButton, Window, div, prelude::*, px, rgba};
use gpui_component::{
    FocusTrapElement, StyledExt,
    button::{Button, ButtonVariants},
};

impl Workspace {
    pub(super) fn close_editor(&mut self, cx: &mut Context<Self>) {
        self.editor = None;
        self.discard_return_focus = None;
        self.message.clear();
        cx.notify();
    }

    pub(super) fn cancel_discard(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(focus) = self.discard_return_focus.take() {
            window.focus(&focus, cx);
            cx.notify();
        }
    }

    pub(super) fn request_editor_dismiss(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.busy || self.editor.is_none() {
            return;
        }
        if self.discard_return_focus.is_some() {
            self.cancel_discard(window, cx);
            return;
        }
        if self.editor_dirty {
            self.discard_return_focus = Some(
                window
                    .focused(cx)
                    .unwrap_or_else(|| self.editor_focus.clone()),
            );
            window.focus(&self.discard_accept_focus, cx);
            cx.notify();
            return;
        }
        self.close_editor(cx);
    }

    pub(super) fn discard_confirmation(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = Palette::get(cx);
        div()
            .id("discard-backdrop")
            .absolute()
            .inset_0()
            .flex()
            .items_center()
            .justify_center()
            .bg(rgba(0x00000040))
            .occlude()
            .on_click(cx.listener(|view, _, window, cx| {
                view.cancel_discard(window, cx);
                cx.stop_propagation();
            }))
            .child(
                div()
                    .id("discard-dialog")
                    .role(gpui::Role::AlertDialog)
                    .aria_label("Discard unsaved changes?")
                    .a11y_synthetic_children(|builder| builder.parent_node().set_modal())
                    .v_flex()
                    .w(px(420.))
                    .m_6()
                    .rounded_xl()
                    .border_1()
                    .border_color(palette.line)
                    .bg(palette.card)
                    .shadow_xl()
                    .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                    .on_mouse_up(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                    .child(
                        div()
                            .p_5()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child("Discard unsaved changes?"),
                    )
                    .child(
                        div()
                            .h_flex()
                            .justify_end()
                            .gap_2()
                            .p_4()
                            .border_t_1()
                            .border_color(palette.line)
                            .child(
                                Button::new("cancel-discard")
                                    .label("Cancel")
                                    .ghost()
                                    .on_click(cx.listener(|view, _, window, cx| {
                                        view.cancel_discard(window, cx)
                                    })),
                            )
                            .child(
                                Button::new("confirm-discard")
                                    .label("Continue")
                                    .danger()
                                    .track_focus(&self.discard_accept_focus)
                                    .on_click(cx.listener(|view, _, _, cx| view.close_editor(cx))),
                            ),
                    )
                    .focus_trap("discard-focus", &self.discard_focus),
            )
    }
}
