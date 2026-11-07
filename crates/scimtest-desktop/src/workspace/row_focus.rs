use gpui::{
    App, Bounds, Div, FocusHandle, IntoElement, Pixels, RenderOnce, ScrollHandle, SharedString,
    Stateful, Window, canvas, prelude::*, px,
};

#[derive(IntoElement)]
pub(super) struct Row {
    pub id: String,
    pub body: Stateful<Div>,
    pub scroll: ScrollHandle,
}

struct Visibility {
    focus: FocusHandle,
    revealed: Option<(FocusHandle, Bounds<Pixels>)>,
}

impl RenderOnce for Row {
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let state = window.use_keyed_state(
            SharedString::from(format!("row-focus:{}", self.id)),
            cx,
            |_, cx| Visibility {
                focus: cx.focus_handle().tab_stop(false),
                revealed: None,
            },
        );
        let focus = state.read(cx).focus.clone();
        self.body.relative().track_focus(&focus).child(
            canvas(
                move |bounds, window, cx| {
                    let viewport = self.scroll.bounds();
                    let target = focus
                        .contains_focused(window, cx)
                        .then(|| window.focused(cx).map(|focused| (focused, viewport)))
                        .flatten();
                    let reveal = state.update(cx, |state, _| {
                        let changed = state.revealed != target;
                        let reveal = changed && target.is_some();
                        state.revealed = target;
                        reveal
                    });
                    if !reveal || viewport.size.height <= px(0.) {
                        return;
                    }
                    let bounds = bounds.dilate(px(8.));
                    let adjustment = if bounds.top() < viewport.top() {
                        viewport.top() - bounds.top()
                    } else if bounds.bottom() > viewport.bottom() {
                        viewport.bottom() - bounds.bottom()
                    } else {
                        return;
                    };
                    let mut offset = self.scroll.offset();
                    offset.y += adjustment;
                    self.scroll.set_offset(offset);
                    window.refresh();
                },
                |_, _, _, _| {},
            )
            .absolute()
            .inset_0(),
        )
    }
}
