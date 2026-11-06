use super::*;
use gpui::{ScrollDelta, ScrollEvent, TestAppContext, TouchPhase, VisualTestContext, point};

fn fixture<'a>(
    cx: &'a mut TestAppContext,
    body: &str,
) -> (Entity<Information>, &'a mut VisualTestContext) {
    cx.update(gpui_component::init);
    let mut information = None;
    let (_, cx) = cx.add_window_view(|window, cx| {
        let view =
            cx.new(|cx| Information::new("Greendale notes".into(), body.to_owned().into(), cx));
        let focus = view.read(cx).focus.clone();
        window.focus(&focus, cx);
        information = Some(view.clone());
        Root::new(view, window, cx)
    });
    cx.run_until_parked();
    cx.simulate_resize(size(px(620.), px(480.)));
    cx.update(|window, cx| {
        window.activate_window();
        window.draw(cx).clear(cx);
    });
    (information.unwrap(), cx)
}

#[gpui::test]
fn long_information_supports_wheel_keyboard_and_resize(cx: &mut TestAppContext) {
    let body = (1..=60)
        .map(|chapter| format!("## Greendale chapter {chapter}\n\nTroy and Abed verify directory, OIDC, SAML and SCIM behavior at Greendale Community College."))
        .collect::<Vec<_>>()
        .join("\n\n");
    let (view, cx) = fixture(cx, &body);
    let list = cx.update(|_, cx| view.read(cx).text.read(cx).list_state().clone());
    assert!(list.item_count() > 60);
    assert!(list.max_offset_for_scrollbar().y > px(0.));
    assert_eq!(list.scroll_px_offset_for_scrollbar().y, px(0.));
    cx.simulate_keystrokes("pagedown");
    cx.update(|window, cx| window.draw(cx).clear(cx));
    assert!(list.scroll_px_offset_for_scrollbar().y < px(0.));
    cx.simulate_keystrokes("home");
    cx.update(|window, cx| window.draw(cx).clear(cx));
    assert_eq!(list.scroll_px_offset_for_scrollbar().y, px(0.));
    cx.simulate_event(ScrollEvent {
        position: list.viewport_bounds().center(),
        delta: ScrollDelta::Lines(point(0., -4.)),
        modifiers: Default::default(),
        touch_phase: TouchPhase::Moved,
        source: Default::default(),
    });
    cx.update(|window, cx| window.draw(cx).clear(cx));
    assert!(list.scroll_px_offset_for_scrollbar().y < px(0.));
    for viewport in [size(px(620.), px(480.)), size(px(400.), px(280.))] {
        cx.simulate_resize(viewport);
        cx.update(|window, cx| {
            assert_eq!(window.viewport_size(), viewport);
            window.draw(cx).clear(cx);
        });
        cx.simulate_keystrokes("end");
        cx.update(|window, cx| {
            window.draw(cx).clear(cx);
            let bounds = list.viewport_bounds();
            assert!(bounds.top() > px(0.));
            assert!(
                bounds.bottom() <= viewport.height - px(45.),
                "{bounds:?} in {viewport:?}"
            );
            assert_eq!(list.is_scrolled_to_end(), Some(true));
            let last = list.bounds_for_item(list.item_count() - 1).unwrap();
            assert!(last.top() >= bounds.top(), "{last:?} outside {bounds:?}");
            assert!(
                last.bottom() <= bounds.bottom(),
                "{last:?} outside {bounds:?}"
            );
        });
        let before = list.scroll_px_offset_for_scrollbar().y;
        cx.simulate_keystrokes("pageup");
        cx.update(|window, cx| window.draw(cx).clear(cx));
        assert!(list.scroll_px_offset_for_scrollbar().y > before);
        let document_end = if cfg!(target_os = "macos") {
            "cmd-down"
        } else {
            "ctrl-end"
        };
        cx.simulate_keystrokes(document_end);
        cx.update(|window, cx| window.draw(cx).clear(cx));
        assert_eq!(list.is_scrolled_to_end(), Some(true));
    }
}

#[gpui::test]
fn scrolling_keeps_selection_and_done_keyboard_activation(cx: &mut TestAppContext) {
    let body = (1..=60)
        .map(|chapter| format!("## Greendale chapter {chapter}\n\nTroy and Abed review the update at Greendale Community College."))
        .collect::<Vec<_>>()
        .join("\n\n");
    let (view, cx) = fixture(cx, &body);
    let list = cx.update(|_, cx| view.read(cx).text.read(cx).list_state().clone());
    assert!(list.max_offset_for_scrollbar().y > px(0.));
    cx.update(|window, cx| {
        let focus = view.read(cx).text.read(cx).focus_handle().clone();
        window.focus(&focus, cx);
    });
    let select_all = if cfg!(target_os = "macos") {
        "cmd-a"
    } else {
        "ctrl-a"
    };
    cx.simulate_keystrokes(select_all);
    let selected = cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        let selected = view.read(cx).text.read(cx).selected_text();
        assert!(selected.contains("Troy and Abed"));
        selected
    });
    assert_eq!(list.scroll_px_offset_for_scrollbar().y, px(0.));
    cx.simulate_keystrokes("end");
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        assert!(list.scroll_px_offset_for_scrollbar().y < px(0.));
        assert_eq!(view.read(cx).text.read(cx).selected_text(), selected);
    });
    cx.simulate_keystrokes("home");
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        assert_eq!(list.scroll_px_offset_for_scrollbar().y, px(0.));
        assert_eq!(view.read(cx).text.read(cx).selected_text(), selected);
    });
    cx.simulate_keystrokes("tab");
    cx.update(|window, cx| window.draw(cx).clear(cx));
    let keystroke =
        cx.update(|_, cx| gpui::Keystroke::parse_with_os("space", cx.platform_info().os).unwrap());
    cx.simulate_event(gpui::KeyDownEvent {
        keystroke: keystroke.clone(),
        is_held: false,
        prefer_character_input: false,
    });
    cx.simulate_event(gpui::KeyUpEvent { keystroke });
    cx.read(|cx| assert!(cx.windows().is_empty(), "Done did not close the window"));
}
