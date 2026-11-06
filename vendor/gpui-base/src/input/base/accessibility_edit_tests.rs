use super::*;
use gpui::TestAppContext;
use gpui::accesskit::{ActionData, TextSelection};

fn range<M: InputModeKind>(
    state: &Entity<InputBaseState<M>>,
    range: Range<usize>,
    window: &mut Window,
    cx: &mut App,
) -> TextSelection {
    state.update(cx, |state, cx| state.set_selected_range(range, cx));
    window.draw(cx).clear(cx);
    state
        .read(cx)
        .accessibility_text
        .borrow_mut()
        .as_mut()
        .unwrap()
        .selection_for_test()
}

#[gpui::test]
fn range_edits_preserve_unicode_and_undo_without_auto_closing(cx: &mut TestAppContext) {
    cx.update(crate::init);
    let original = "Troy 🦀\nGreendale";
    let (state, cx) = cx.add_window_view(|window, cx| {
        let mut state = crate::input::EditorState::new(window, cx)
            .language("rust")
            .default_value(original);
        state.set_accessibility(InputAccessibility::new(Some(
            gpui::Role::MultilineTextInput,
        )));
        state
    });
    cx.update(|window, cx| {
        let selection = range(&state, 5..9, window, cx);
        state.update(cx, |state, cx| {
            state.set_selected_range(0..0, cx);
            state.handle_accessibility_edit(
                Some(&ActionData::ReplaceText {
                    selection,
                    value: "(".into(),
                }),
                window,
                cx,
            );
            assert_eq!(state.value(), "Troy (\nGreendale");
            assert_eq!(state.selected_range(), 6..6);
            state.undo(&Undo, window, cx);
            assert_eq!(state.value(), original);
        });
    });
}

#[gpui::test]
fn explicit_clipboard_ranges_preserve_selection_and_use_the_editor_history(
    cx: &mut TestAppContext,
) {
    cx.update(crate::init);
    let (state, cx) = cx.add_window_view(|window, cx| {
        let mut state = crate::input::InputState::new(window, cx).default_value("Troy 🦀 Barnes");
        state.set_accessibility(InputAccessibility::new(Some(gpui::Role::TextInput)));
        state
    });
    cx.update(|window, cx| {
        let selection = range(&state, 5..9, window, cx);
        state.update(cx, |state, cx| {
            state.set_selected_range(0..0, cx);
            state.set_readonly(true, cx);
            state.handle_accessibility_edit(Some(&ActionData::CopyText(selection)), window, cx);
            assert_eq!(cx.read_from_clipboard().unwrap().text().unwrap(), "🦀");
            assert_eq!(state.selected_range(), 0..0);
            state.set_readonly(false, cx);
            state.handle_accessibility_edit(Some(&ActionData::CutText(selection)), window, cx);
            assert_eq!(state.value(), "Troy  Barnes");
            assert_eq!(cx.read_from_clipboard().unwrap().text().unwrap(), "🦀");
            state.undo(&Undo, window, cx);
            assert_eq!(state.value(), "Troy 🦀 Barnes");
        });
        let position = range(&state, 0..0, window, cx).focus;
        state.update(cx, |state, cx| {
            state.set_selected_range(state.text.len()..state.text.len(), cx);
            state.handle_accessibility_edit(Some(&ActionData::PasteText(position)), window, cx);
            assert_eq!(state.value(), "🦀Troy 🦀 Barnes");
            state.undo(&Undo, window, cx);
            assert_eq!(state.value(), "Troy 🦀 Barnes");
        });
    });
}

#[gpui::test]
fn range_edits_recheck_permissions_privacy_node_ids_and_document_revision(cx: &mut TestAppContext) {
    cx.update(crate::init);
    let (state, cx) = cx.add_window_view(|window, cx| {
        let mut state = crate::input::InputState::new(window, cx).default_value("Troy Barnes");
        state.set_accessibility(InputAccessibility::new(Some(gpui::Role::TextInput)));
        state
    });
    cx.update(|window, cx| {
        let selection = range(&state, 0..4, window, cx);
        let edit = ActionData::ReplaceText {
            selection,
            value: "Jeff".into(),
        };
        cx.write_to_clipboard(ClipboardItem::new_string("sentinel".into()));
        state.update(cx, |state, cx| {
            for mode in ["readonly", "disabled", "masked", "secret"] {
                state.readonly = mode == "readonly";
                state.disabled = mode == "disabled";
                state.masked = mode == "masked";
                state.set_accessibility(
                    InputAccessibility::new(Some(gpui::Role::TextInput))
                        .with_value_exposed(mode != "secret"),
                );
                state.handle_accessibility_edit(Some(&edit), window, cx);
                state.handle_accessibility_edit(Some(&ActionData::CutText(selection)), window, cx);
                state.handle_accessibility_edit(
                    Some(&ActionData::PasteText(selection.anchor)),
                    window,
                    cx,
                );
                if mode != "readonly" {
                    state.handle_accessibility_edit(
                        Some(&ActionData::CopyText(selection)),
                        window,
                        cx,
                    );
                }
                assert_eq!(state.value(), "Troy Barnes");
                assert_eq!(
                    cx.read_from_clipboard().unwrap().text().unwrap(),
                    "sentinel"
                );
            }
            state.readonly = false;
            state.disabled = false;
            state.masked = false;
            state.set_accessibility(InputAccessibility::new(Some(gpui::Role::TextInput)));
            let mut foreign = selection;
            foreign.anchor.node = gpui::accesskit::NodeId(999);
            state.handle_accessibility_edit(
                Some(&ActionData::ReplaceText {
                    selection: foreign,
                    value: "Jeff".into(),
                }),
                window,
                cx,
            );
            assert_eq!(state.value(), "Troy Barnes");
            state.set_value("Jeff Winger", window, cx);
            state.handle_accessibility_edit(Some(&edit), window, cx);
            assert_eq!(state.value(), "Jeff Winger");
        });
    });
}

#[gpui::test]
fn range_edits_and_clipboard_pastes_apply_the_input_validator(cx: &mut TestAppContext) {
    cx.update(crate::init);
    let (state, cx) = cx.add_window_view(|window, cx| {
        let mut state = crate::input::InputState::new(window, cx)
            .default_value("Troy")
            .validate(|value, _| value.chars().all(char::is_alphabetic));
        state.set_accessibility(InputAccessibility::new(Some(gpui::Role::TextInput)));
        state
    });
    cx.update(|window, cx| {
        let selection = range(&state, 4..4, window, cx);
        state.update(cx, |state, cx| {
            state.handle_accessibility_edit(
                Some(&ActionData::ReplaceText {
                    selection,
                    value: "42".into(),
                }),
                window,
                cx,
            );
            assert_eq!(state.value(), "Troy");
            cx.write_to_clipboard(ClipboardItem::new_string("42".into()));
            state.handle_accessibility_edit(
                Some(&ActionData::PasteText(selection.focus)),
                window,
                cx,
            );
            assert_eq!(state.value(), "Troy");
            cx.write_to_clipboard(ClipboardItem::new_string("Barnes".into()));
            state.handle_accessibility_edit(
                Some(&ActionData::PasteText(selection.focus)),
                window,
                cx,
            );
            assert_eq!(state.value(), "TroyBarnes");
            state.undo(&Undo, window, cx);
            assert_eq!(state.value(), "Troy");
        });
    });
}
