use super::*;
use gpui::{Focusable, TestAppContext, VisualTestContext, px};
use gpui_component::Root;

mod account;

fn fixture(
    cx: &mut TestAppContext,
) -> (
    Entity<Workspace>,
    &mut VisualTestContext,
    tempfile::TempDir,
    tokio::runtime::Runtime,
) {
    fixture_with_tunnel(cx, None)
}

fn fixture_with_tunnel(
    cx: &mut TestAppContext,
    config: Option<scimtest_core::tunnel::Config>,
) -> (
    Entity<Workspace>,
    &mut VisualTestContext,
    tempfile::TempDir,
    tokio::runtime::Runtime,
) {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    let environment = store
        .create_environment(EnvironmentInput {
            name: "Greendale Portal".into(),
            ..Default::default()
        })
        .unwrap();
    store.seed_sample(&environment.id).unwrap();
    let identity = scimtest_core::oidc::Identity::new(store.clone());
    let scim = scimtest_core::scim::Service::new(store.clone());
    let executor = tokio::runtime::Runtime::new().unwrap();
    let tunnel = {
        let _entered = executor.enter();
        scimtest_core::tunnel::Service::new(store.clone(), config, 1).unwrap()
    };
    let handle = executor.handle().clone();
    let directories = store.snapshot().unwrap();
    cx.update(gpui_component::init);
    let mut workspace = None;
    let (_, cx) = cx.add_window_view(|window, cx| {
        let updates =
            cx.new(|cx| crate::updates::Controller::new(None, handle.clone(), store.clone(), cx));
        let view = cx.new(|cx| {
            Workspace::new(
                store,
                identity,
                scim,
                tunnel,
                handle,
                directories,
                "http://127.0.0.1:1".into(),
                updates,
                window,
                cx,
            )
        });
        Workspace::install_shortcuts(&view, window.window_handle(), cx);
        workspace = Some(view.clone());
        Root::new(view, window, cx)
    });
    cx.update(|window, cx| {
        window.activate_window();
        window.draw(cx).clear(cx);
    });
    (workspace.unwrap(), cx, temporary, executor)
}

fn press_space(cx: &mut VisualTestContext) {
    let keystroke =
        cx.update(|_, cx| gpui::Keystroke::parse_with_os("space", cx.platform_info().os).unwrap());
    cx.simulate_event(gpui::KeyDownEvent {
        keystroke: keystroke.clone(),
        is_held: false,
        prefer_character_input: false,
    });
    cx.simulate_event(gpui::KeyUpEvent { keystroke });
    cx.update(|window, cx| window.draw(cx).clear(cx));
}

#[gpui::test]
fn keyboard_focus_reveals_directory_rows_without_overriding_manual_scroll(cx: &mut TestAppContext) {
    let (view, cx, _temporary, _executor) = fixture(cx);
    cx.simulate_resize(gpui::size(px(1000.), px(600.)));
    cx.update(|window, cx| {
        assert_eq!(window.viewport_size(), gpui::size(px(1000.), px(600.)));
        window.draw(cx).clear(cx);
        let focus = view.read(cx).focus.clone();
        window.focus(&focus, cx);
    });
    let mut scrolled = false;
    for _ in 0..100 {
        cx.simulate_keystrokes("tab");
        cx.update(|window, cx| {
            window.draw(cx).clear(cx);
            window.draw(cx).clear(cx);
            scrolled = view.read(cx).table_scroll.offset().y < px(0.);
        });
        if scrolled {
            break;
        }
    }
    assert!(
        scrolled,
        "tabbing to clipped rows must reveal their controls"
    );
    cx.update(|window, cx| {
        view.read(cx).table_scroll.set_offset(Default::default());
        window.draw(cx).clear(cx);
        window.draw(cx).clear(cx);
        assert_eq!(view.read(cx).table_scroll.offset().y, px(0.));
    });
    cx.simulate_keystrokes("tab");
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        window.draw(cx).clear(cx);
        assert!(view.read(cx).table_scroll.offset().y < px(0.));
    });
}

#[gpui::test]
fn group_members_reveal_keyboard_focus_and_preserve_manual_scroll(cx: &mut TestAppContext) {
    let (view, cx, _temporary, _executor) = fixture(cx);
    cx.simulate_resize(gpui::size(px(960.), px(640.)));
    let last_id = cx.update(|window, cx| {
        assert_eq!(window.viewport_size(), gpui::size(px(960.), px(640.)));
        view.update(cx, |view, cx| {
            let environment = view.selected.clone().unwrap();
            for (first, last) in [
                ("Vicki", "Cooper"),
                ("Buzz", "Hickey"),
                ("Frankie", "Dart"),
                ("Elroy", "Patashnik"),
                ("Garrett", "Lambert"),
                ("Todd", "Jacobson"),
            ] {
                view.store
                    .create_user(
                        &environment,
                        UserInput {
                            given_name: first.into(),
                            family_name: last.into(),
                            username: first.to_lowercase(),
                            email: format!("{}@greendale.edu", first.to_lowercase()),
                            active: true,
                            ..Default::default()
                        },
                    )
                    .unwrap();
            }
            view.directories = view.store.snapshot().unwrap();
            let last_id = view.directory().unwrap().users.last().unwrap().id.clone();
            view.edit_group(None, window, cx);
            let Some(Editor::Group { name, .. }) = &view.editor else {
                panic!("group form must be open");
            };
            name.update(cx, |state, cx| {
                state.set_value("Greendale keyboard group", window, cx)
            });
            last_id
        })
    });
    cx.update(|window, cx| window.draw(cx).clear(cx));
    for _ in 0..17 {
        cx.simulate_keystrokes("tab");
        cx.update(|window, cx| {
            window.draw(cx).clear(cx);
            window.draw(cx).clear(cx);
        });
    }
    let keystroke =
        cx.update(|_, cx| gpui::Keystroke::parse_with_os("space", cx.platform_info().os).unwrap());
    cx.simulate_event(gpui::KeyDownEvent {
        keystroke: keystroke.clone(),
        is_held: false,
        prefer_character_input: false,
    });
    cx.simulate_event(gpui::KeyUpEvent { keystroke });
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        let workspace = view.read(cx);
        let Some(Editor::Group { members, .. }) = &workspace.editor else {
            panic!("group form must be open");
        };
        assert!(members.contains(&last_id));
        let scroll = &workspace.member_scroll;
        assert!(scroll.offset().y < px(0.));
        let row = scroll.bounds_for_item(15).unwrap() + scroll.offset();
        assert!(row.top() >= scroll.bounds().top());
        // The two-column member card's padding and border can sit just past the
        // viewport edge while its focused checkbox stays visible.
        assert!(row.bottom() <= scroll.bounds().bottom() + px(24.));
        scroll.set_offset(Default::default());
        window.draw(cx).clear(cx);
        window.draw(cx).clear(cx);
        assert_eq!(view.read(cx).member_scroll.offset().y, px(0.));
    });
    cx.simulate_keystrokes("shift-tab");
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        window.draw(cx).clear(cx);
        assert!(view.read(cx).member_scroll.offset().y < px(0.));
    });
    cx.dispatch_action(crate::menus::Save);
    cx.executor().run_until_parked();
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        let workspace = view.read(cx);
        assert!(workspace.editor.is_none(), "{}", workspace.message);
        let group = workspace
            .directory()
            .unwrap()
            .groups
            .iter()
            .find(|group| group.fields.display_name == "Greendale keyboard group")
            .unwrap();
        assert_eq!(group.fields.member_ids, vec![last_id]);
    });
}

#[gpui::test]
fn tabbing_reveals_user_fields(cx: &mut TestAppContext) {
    let (view, cx, _temporary, _executor) = fixture(cx);
    cx.simulate_resize(gpui::size(px(960.), px(640.)));
    cx.update(|window, cx| {
        assert_eq!(window.viewport_size(), gpui::size(px(960.), px(640.)));
        view.update(cx, |view, cx| {
            view.edit_user(None, window, cx);
            view.disclosures.extend(["user-enterprise", "user-custom"]);
        });
        window.draw(cx).clear(cx);
    });
    let mut visited = std::collections::BTreeSet::new();
    for _ in 0..24 {
        cx.update(|window, cx| {
            window.draw(cx).clear(cx);
            window.draw(cx).clear(cx);
            let Some(Editor::User {
                fields, attributes, ..
            }) = &view.read(cx).editor
            else {
                panic!("user form must be open");
            };
            for (index, state) in fields.iter().enumerate() {
                if state.focus_handle(cx).is_focused(window) {
                    let bounds = state.read(cx).input_bounds();
                    assert!(
                        bounds.top() >= px(64.) && bounds.bottom() <= px(580.),
                        "field {index}: {bounds:?}"
                    );
                    visited.insert(index);
                }
            }
            if attributes.focus_handle(cx).is_focused(window) {
                let bounds = attributes.read(cx).input_bounds();
                assert!(
                    bounds.top() >= px(64.) && bounds.bottom() <= px(580.),
                    "attributes: {bounds:?}"
                );
                visited.insert(9);
            }
        });
        cx.simulate_keystrokes("tab");
    }
    assert_eq!(visited.len(), 10);
}

#[gpui::test]
fn tabbing_reveals_environment_fields(cx: &mut TestAppContext) {
    use gpui_component::{WindowExt, input::AnyInputState};
    let (view, cx, _temporary, _executor) = fixture(cx);
    for (section, count) in [
        (environment::Section::General, 3),
        (environment::Section::Oidc, 11),
        (environment::Section::Saml, 11),
        (environment::Section::Scim, 2),
    ] {
        cx.simulate_resize(gpui::size(px(960.), px(640.)));
        cx.update(|window, cx| {
            assert_eq!(window.viewport_size(), gpui::size(px(960.), px(640.)));
            view.update(cx, |view, cx| {
                let environment = view.directory().unwrap().environment.clone();
                view.edit_environment(Some(&environment), window, cx);
                let Some(Editor::Environment { settings, .. }) = &mut view.editor else {
                    panic!("settings must be open");
                };
                settings.section = section;
                view.disclosures
                    .extend(["oidc-claims", "saml-signing", "saml-mappings"]);
            });
            window.draw(cx).clear(cx);
            let focus = view.read(cx).editor_focus.clone();
            window.focus(&focus, cx);
        });
        for key in ["tab", "shift-tab"] {
            let mut visited = Vec::new();
            for _ in 0..72 {
                cx.simulate_keystrokes(key);
                cx.update(|window, cx| {
                    window.draw(cx).clear(cx);
                    window.draw(cx).clear(cx);
                    assert!(view.read(cx).editor_focus.contains_focused(window, cx));
                    if let Some(input) = window.focused_input(cx) {
                        let bounds = match &input {
                            AnyInputState::Input(state) => state.read(cx).input_bounds(),
                            AnyInputState::Textarea(state) => state
                                .read(cx)
                                .prepaint_caret_geometry()
                                .expect("focused textarea must have a caret")
                                .cursor_bounds(),
                            _ => panic!("unexpected field type"),
                        };
                        assert!(
                            bounds.top() >= px(64.) && bounds.bottom() <= px(580.),
                            "{key}: {bounds:?}"
                        );
                        let focus = input.focus_handle(cx);
                        if !visited.contains(&focus) {
                            visited.push(focus);
                        }
                    }
                });
            }
            assert_eq!(visited.len(), count, "{key}");
        }
    }
}

#[gpui::test]
fn editor_keyboard_focus_stays_inside_the_sheet_and_escape_restores_the_workspace(
    cx: &mut TestAppContext,
) {
    let (view, cx, _temporary, _executor) = fixture(cx);
    cx.update(|window, cx| view.update(cx, |view, cx| view.edit_user(None, window, cx)));
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        let view = view.read(cx);
        let Some(Editor::User { fields, .. }) = &view.editor else {
            panic!("user form must be open");
        };
        assert!(fields[3].focus_handle(cx).is_focused(window));
        assert!(view.editor_focus.contains_focused(window, cx));
    });
    for key in ["tab", "shift-tab"] {
        for _ in 0..72 {
            cx.simulate_keystrokes(key);
            cx.update(|window, cx| {
                window.draw(cx).clear(cx);
                assert!(
                    view.read(cx).editor_focus.contains_focused(window, cx),
                    "{key} escaped the modal"
                );
            });
        }
    }
    cx.simulate_keystrokes("escape");
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        assert!(view.read(cx).editor.is_none());
        assert!(view.read(cx).focus.contains_focused(window, cx));
    });
}

#[gpui::test]
fn account_screen_moves_focus_and_restores_the_previous_control(cx: &mut TestAppContext) {
    let (view, cx, _temporary, _executor) = fixture(cx);
    cx.update(|window, cx| {
        let focus = view.read(cx).search.focus_handle(cx);
        window.focus(&focus, cx);
        window.draw(cx).clear(cx);
        view.update(cx, |view, cx| {
            view.account_open = true;
            cx.notify();
        });
        window.draw(cx).clear(cx);
        assert!(!focus.is_focused(window), "unmounted search retained focus");
        assert!(view.read(cx).account_focus.contains_focused(window, cx));
    });
    for key in ["tab", "shift-tab"] {
        for _ in 0..8 {
            cx.simulate_keystrokes(key);
            cx.update(|window, cx| {
                window.draw(cx).clear(cx);
                assert!(!view.read(cx).search.focus_handle(cx).is_focused(window));
                assert!(view.read(cx).account_focus.contains_focused(window, cx));
            });
        }
    }
    cx.update(|window, cx| {
        view.update(cx, |view, cx| {
            view.account_open = false;
            cx.notify();
        });
        window.draw(cx).clear(cx);
        assert!(view.read(cx).search.focus_handle(cx).is_focused(window));
    });
    cx.simulate_input("Troy");
    cx.update(|_, cx| assert_eq!(view.read(cx).search.read(cx).value().as_str(), "Troy"));
}

#[gpui::test]
fn account_keyboard_round_trip_restores_the_toolbar_trigger(cx: &mut TestAppContext) {
    let (view, cx, _temporary, _executor) = fixture(cx);
    let space = |cx: &mut VisualTestContext| {
        let keystroke = cx.update(|_, cx| {
            gpui::Keystroke::parse_with_os("space", cx.platform_info().os).unwrap()
        });
        cx.simulate_event(gpui::KeyDownEvent {
            keystroke: keystroke.clone(),
            is_held: false,
            prefer_character_input: false,
        });
        cx.simulate_event(gpui::KeyUpEvent { keystroke });
        cx.update(|window, cx| window.draw(cx).clear(cx));
    };
    cx.update(|window, cx| {
        let focus = view.read(cx).focus.clone();
        window.focus(&focus, cx);
    });
    cx.simulate_keystrokes("tab tab tab");
    let trigger = cx.update(|window, cx| window.focused(cx).unwrap());
    space(cx);
    cx.update(|_, cx| assert!(view.read(cx).account_open));
    cx.simulate_keystrokes("tab");
    space(cx);
    cx.update(|window, cx| {
        assert!(!view.read(cx).account_open);
        assert!(trigger.is_focused(window));
    });
    space(cx);
    cx.update(|_, cx| assert!(view.read(cx).account_open));
}

#[gpui::test]
fn escape_preserves_an_unsaved_editor(cx: &mut TestAppContext) {
    let (view, cx, _temporary, _executor) = fixture(cx);
    cx.update(|window, cx| {
        view.update(cx, |view, cx| view.edit_user(None, window, cx));
        window.draw(cx).clear(cx);
    });
    cx.simulate_input("troy.unsaved");
    cx.simulate_keystrokes("escape");
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        assert!(view.read(cx).editor.is_some(), "Escape discarded the draft");
        assert!(view.read(cx).discard_return_focus.is_some());
        assert!(view.read(cx).discard_accept_focus.is_focused(window));
    });
    for key in ["tab", "shift-tab"] {
        for _ in 0..8 {
            cx.simulate_keystrokes(key);
            cx.update(|window, cx| {
                window.draw(cx).clear(cx);
                assert!(view.read(cx).discard_focus.contains_focused(window, cx));
            });
        }
    }
    cx.dispatch_action(crate::menus::Save);
    cx.executor().run_until_parked();
    cx.update(|_, cx| {
        assert!(view.read(cx).discard_return_focus.is_some());
        assert!(!view.read(cx).busy);
    });
    cx.simulate_keystrokes("escape");
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        let workspace = view.read(cx);
        assert!(workspace.discard_return_focus.is_none());
        let Some(Editor::User { fields, .. }) = &workspace.editor else {
            panic!("draft must still be open");
        };
        assert_eq!(fields[3].read(cx).value().as_str(), "troy.unsaved");
        assert!(fields[3].focus_handle(cx).is_focused(window));
    });
    cx.simulate_keystrokes("escape");
    cx.update(|window, cx| window.draw(cx).clear(cx));
    press_space(cx);
    cx.update(|window, cx| {
        assert!(view.read(cx).editor.is_none());
        assert!(view.read(cx).focus.contains_focused(window, cx));
        assert!(
            !view
                .read(cx)
                .directory()
                .unwrap()
                .users
                .iter()
                .any(|user| { user.fields.username == "troy.unsaved" })
        );
    });
}

#[gpui::test]
fn backdrop_dismisses_an_unchanged_editor(cx: &mut TestAppContext) {
    let (view, cx, _temporary, _executor) = fixture(cx);
    cx.simulate_resize(gpui::size(px(960.), px(640.)));
    cx.update(|window, cx| {
        assert_eq!(window.viewport_size(), gpui::size(px(960.), px(640.)));
        view.update(cx, |view, cx| view.edit_user(None, window, cx));
        window.draw(cx).clear(cx);
    });
    cx.simulate_click(gpui::point(px(10.), px(100.)), Default::default());
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        assert!(
            view.read(cx).editor.is_none(),
            "Backdrop did not dismiss the sheet"
        );
    });
}

#[gpui::test]
fn backdrop_requires_both_ends_outside_the_sheet_and_guards_dirty_forms(cx: &mut TestAppContext) {
    let (view, cx, _temporary, _executor) = fixture(cx);
    cx.simulate_resize(gpui::size(px(960.), px(640.)));
    cx.update(|window, cx| {
        assert_eq!(window.viewport_size(), gpui::size(px(960.), px(640.)));
        view.update(cx, |view, cx| view.edit_group(None, window, cx));
        window.draw(cx).clear(cx);
    });
    let inside = cx.update(|_, cx| {
        let Some(Editor::Group { name, .. }) = &view.read(cx).editor else {
            panic!("group form must be open");
        };
        name.read(cx).input_bounds().center()
    });
    let outside = gpui::point(px(10.), px(100.));
    cx.simulate_event(gpui::MouseDownEvent {
        position: inside,
        button: gpui::MouseButton::Left,
        click_count: 1,
        modifiers: Default::default(),
        first_mouse: false,
    });
    cx.simulate_event(gpui::MouseUpEvent {
        position: outside,
        button: gpui::MouseButton::Left,
        click_count: 1,
        modifiers: Default::default(),
    });
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        assert!(
            view.read(cx).editor.is_some(),
            "selection drag dismissed the form"
        );
    });
    cx.simulate_event(gpui::MouseDownEvent {
        position: outside,
        button: gpui::MouseButton::Left,
        click_count: 1,
        modifiers: Default::default(),
        first_mouse: false,
    });
    cx.simulate_event(gpui::MouseUpEvent {
        position: inside,
        button: gpui::MouseButton::Left,
        click_count: 1,
        modifiers: Default::default(),
    });
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        assert!(
            view.read(cx).editor.is_some(),
            "release inside dismissed the form"
        );
        let Some(Editor::Group { name, .. }) = &view.read(cx).editor else {
            panic!("group form must remain open");
        };
        let focus = name.focus_handle(cx);
        window.focus(&focus, cx);
    });
    cx.simulate_input("Greendale study group");
    cx.simulate_click(outside, Default::default());
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        assert!(view.read(cx).discard_return_focus.is_some());
    });
    cx.simulate_click(outside, Default::default());
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        assert!(view.read(cx).discard_return_focus.is_none());
        let Some(Editor::Group { name, .. }) = &view.read(cx).editor else {
            panic!("group form must remain open");
        };
        assert_eq!(name.read(cx).value().as_str(), "Greendale study group");
        assert!(name.focus_handle(cx).is_focused(window));
    });
}

#[gpui::test]
fn reverted_edits_and_checkbox_changes_still_require_confirmation(cx: &mut TestAppContext) {
    let (view, cx, _temporary, _executor) = fixture(cx);
    cx.update(|window, cx| {
        view.update(cx, |view, cx| view.edit_user(None, window, cx));
        window.draw(cx).clear(cx);
    });
    cx.simulate_input("Troy");
    cx.simulate_keystrokes("backspace backspace backspace backspace escape");
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        assert!(view.read(cx).discard_return_focus.is_some());
        let Some(Editor::User { fields, .. }) = &view.read(cx).editor else {
            panic!("user form must remain open");
        };
        assert!(fields[3].read(cx).value().is_empty());
        view.update(cx, |view, cx| view.close_editor(cx));
        window.draw(cx).clear(cx);
        view.update(cx, |view, cx| view.edit_user(None, window, cx));
        window.draw(cx).clear(cx);
        assert!(!view.read(cx).editor_dirty);
    });
    cx.simulate_keystrokes("tab tab tab tab");
    press_space(cx);
    cx.simulate_keystrokes("escape");
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        assert!(view.read(cx).discard_return_focus.is_some());
        let Some(Editor::User { active, .. }) = &view.read(cx).editor else {
            panic!("user form must remain open");
        };
        assert!(!active);
    });
    cx.simulate_keystrokes("shift-tab");
    press_space(cx);
    cx.update(|_, cx| {
        assert!(view.read(cx).discard_return_focus.is_none());
        assert!(view.read(cx).editor.is_some());
    });
}

#[gpui::test]
fn replacing_a_lifecycle_form_resets_dirty_state_and_detaches_old_inputs(cx: &mut TestAppContext) {
    let (view, cx, _temporary, _executor) = fixture(cx);
    let old_input = cx.update(|window, cx| {
        view.update(cx, |view, cx| view.edit_lifecycle("joiner", window, cx));
        window.draw(cx).clear(cx);
        let Some(Editor::Lifecycle(form)) = &view.read(cx).editor else {
            panic!("joiner form must be open");
        };
        form.inputs()[0].as_input().unwrap().clone()
    });
    cx.update(|window, cx| {
        old_input.update(cx, |state, cx| state.replace_all("Troy", window, cx));
    });
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        assert!(view.read(cx).editor_dirty);
        view.update(cx, |view, cx| view.edit_lifecycle("mover", window, cx));
        window.draw(cx).clear(cx);
        assert!(!view.read(cx).editor_dirty);
        old_input.update(cx, |state, cx| state.replace_all("Abed", window, cx));
    });
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        assert!(!view.read(cx).editor_dirty);
    });
    cx.simulate_keystrokes("escape");
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        assert!(view.read(cx).editor.is_none());
    });
}

#[gpui::test]
fn saving_preserves_multiline_attributes_and_find_works_after_the_editor_closes(
    cx: &mut TestAppContext,
) {
    let (view, cx, _temporary, _executor) = fixture(cx);
    cx.update(|window, cx| {
        view.update(cx, |view, cx| {
            view.edit_user(None, window, cx);
            let Some(Editor::User {
                fields, attributes, ..
            }) = &view.editor
            else {
                panic!("user form must be open");
            };
            for (index, value) in [
                (0, "Troy"),
                (1, "Barnes"),
                (2, "troy.keyboard@greendale.edu"),
                (3, "troy.keyboard"),
            ] {
                fields[index].update(cx, |state, cx| state.set_value(value, window, cx));
            }
            attributes.update(cx, |state, cx| {
                state.set_value("role=student\ncampus=Greendale", window, cx)
            });
        })
    });
    cx.update(|window, cx| window.draw(cx).clear(cx));
    cx.dispatch_action(crate::menus::Save);
    cx.executor().run_until_parked();
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        let workspace = view.read(cx);
        assert!(workspace.editor.is_none(), "{}", workspace.message);
        let user = workspace
            .directory()
            .unwrap()
            .users
            .iter()
            .find(|user| user.fields.username == "troy.keyboard")
            .unwrap();
        assert_eq!(user.fields.attributes["role"], "student");
        assert_eq!(user.fields.attributes["campus"], "Greendale");
    });
    cx.dispatch_action(crate::menus::SearchDirectory);
    cx.executor().run_until_parked();
    cx.update(|window, cx| {
        window.draw(cx).clear(cx);
        assert!(view.read(cx).search.focus_handle(cx).is_focused(window));
    });
    cx.simulate_input("Troy");
    cx.update(|_, cx| assert_eq!(view.read(cx).search.read(cx).value().as_str(), "Troy"));
}

#[gpui::test]
fn environment_wizard_blocks_next_and_save_until_required_fields_are_set(cx: &mut TestAppContext) {
    let (view, cx, _temporary, _executor) = fixture(cx);
    cx.update(|window, cx| {
        view.update(cx, |view, cx| view.edit_environment(None, window, cx));
        window.draw(cx).clear(cx);
    });
    let wizard = |cx: &mut VisualTestContext| {
        cx.update(|_, cx| {
            let view = view.read(cx);
            let Some(Editor::Environment { settings, .. }) = &view.editor else {
                panic!("environment editor must be open");
            };
            (settings.section.index(), view.message.clone(), view.failed)
        })
    };

    cx.update(|_, cx| view.update(cx, |view, cx| view.set_environment_step(1, cx)));
    let (step, message, failed) = wizard(cx);
    assert_eq!(step, 0);
    assert_eq!(message, "Enter an environment name.");
    assert!(failed);

    cx.update(|window, cx| {
        let name = match &view.read(cx).editor {
            Some(Editor::Environment { name, .. }) => name.clone(),
            _ => panic!("environment editor must be open"),
        };
        name.update(cx, |state, cx| state.set_value("Troy Portal", window, cx));
    });
    cx.update(|_, cx| view.update(cx, |view, cx| view.set_environment_step(1, cx)));
    assert_eq!(wizard(cx).0, 1);

    cx.update(|_, cx| {
        view.update(cx, |view, _| {
            if let Some(Editor::Environment { settings, .. }) = &mut view.editor {
                settings.toggles.insert("oidc_enabled", true);
            }
        })
    });
    cx.update(|_, cx| view.update(cx, |view, cx| view.set_environment_step(0, cx)));
    let directories = cx.update(|_, cx| view.read(cx).directories.len());

    cx.update(|_, cx| view.update(cx, |view, cx| view.save(cx)));
    let (step, message, failed) = wizard(cx);
    assert_eq!(step, 1);
    assert_eq!(message, "OIDC needs Client ID, Redirect URIs.");
    assert!(failed);
    assert_eq!(
        cx.update(|_, cx| view.read(cx).directories.len()),
        directories
    );
}
