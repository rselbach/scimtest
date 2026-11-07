use std::{cell::Cell, rc::Rc};

use gpui::{App, Bounds, ElementId, FocusHandle, Pixels, Subscription, Window, px};

struct Reveal {
    focus: FocusHandle,
    viewport: Rc<Cell<Option<Bounds<Pixels>>>>,
    _blur: Subscription,
}

impl Reveal {
    fn new(focus: &FocusHandle, window: &mut Window, cx: &mut App) -> Self {
        let viewport = Rc::new(Cell::new(None));
        let blurred = viewport.clone();
        Self {
            focus: focus.clone(),
            viewport,
            _blur: window.on_focus_out(focus, cx, move |_, _, _| blurred.set(None)),
        }
    }
}

pub(crate) fn observe(
    id: ElementId,
    focus: FocusHandle,
    enabled: bool,
    window: &mut Window,
    cx: &mut App,
) -> impl FnOnce(Bounds<Pixels>, &mut Window, &mut App) + use<> {
    let state = window.use_keyed_state((id, "focus-reveal"), cx, |window, cx| {
        Reveal::new(&focus, window, cx)
    });
    let viewport = state.update(cx, |state, cx| {
        if state.focus != focus {
            *state = Reveal::new(&focus, window, cx);
        }
        state.viewport.clone()
    });
    move |bounds, window, _| {
        let target = (enabled && focus.is_focused(window)).then(|| window.fully_visible_bounds());
        let changed = viewport.replace(target) != target;
        if changed && target.is_some() && bounds.size.height > px(0.) {
            window.request_autoscroll(bounds.dilate(px(8.)));
        }
    }
}
