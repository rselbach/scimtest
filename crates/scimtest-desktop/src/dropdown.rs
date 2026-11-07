use gpui::{
    App, ClickEvent, Context, ElementId, InteractiveElement, IntoElement, RenderOnce, SharedString,
    Window,
};
use gpui_component::{button::Button, menu::PopupMenu};

type MenuBuilder = Box<dyn Fn(PopupMenu, &mut Window, &mut Context<PopupMenu>) -> PopupMenu>;

pub(crate) trait DropdownMenu {
    fn dropdown_menu(
        self,
        build: impl Fn(PopupMenu, &mut Window, &mut Context<PopupMenu>) -> PopupMenu + 'static,
    ) -> Menu;
}

impl DropdownMenu for Button {
    fn dropdown_menu(
        mut self,
        build: impl Fn(PopupMenu, &mut Window, &mut Context<PopupMenu>) -> PopupMenu + 'static,
    ) -> Menu {
        let id = self.interactivity().element_id.clone().unwrap_or(0.into());
        Menu {
            id: SharedString::from(format!("accessible-menu:{id:?}")).into(),
            button: self,
            build: Box::new(build),
        }
    }
}

#[derive(IntoElement)]
pub(crate) struct Menu {
    id: ElementId,
    button: Button,
    build: MenuBuilder,
}

impl RenderOnce for Menu {
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let focus = window
            .use_keyed_state(self.id, cx, |_, cx| cx.focus_handle())
            .read(cx)
            .clone();
        let button = self
            .button
            .track_focus(&focus)
            .on_click(move |event, window, cx| {
                // Registering a click handler exposes the native press action.
                // The popover handles mouse presses; forward keyboard clicks.
                if matches!(event, ClickEvent::Keyboard(_)) {
                    window.focus(&focus, cx);
                    window.dispatch_action(
                        Box::new(gpui_base::actions::Confirm { secondary: false }),
                        cx,
                    );
                }
            });
        gpui_component::menu::DropdownMenu::dropdown_menu(button, move |menu, window, cx| {
            (self.build)(menu, window, cx).scrollable(true)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui::{AppContext, Bounds, ParentElement, Pixels, Render, TestAppContext, div, px};
    use gpui_base::ElementExt as _;
    use gpui_component::{Root, menu::PopupMenuItem};
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };

    struct Fixture {
        opens: Rc<Cell<usize>>,
        selections: Rc<Cell<usize>>,
        bounds: Rc<RefCell<Vec<Bounds<Pixels>>>>,
    }

    impl Render for Fixture {
        fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
            let opens = self.opens.clone();
            let selections = self.selections.clone();
            let bounds = self.bounds.clone();
            div().child(Button::new("picker").label("Student").dropdown_menu(
                move |mut menu, _, _| {
                    opens.set(opens.get() + 1);
                    for index in 0..bounds.borrow().len() {
                        let selections = selections.clone();
                        let bounds = bounds.clone();
                        menu = menu.item(
                            PopupMenuItem::element(move |_, _| {
                                let bounds = bounds.clone();
                                div()
                                    .child(format!("Greendale class {index:02}"))
                                    .on_prepaint(move |value, _, _| {
                                        bounds.borrow_mut()[index] = value
                                    })
                            })
                            .on_click(move |_, _, _| selections.set(index + 1)),
                        );
                    }
                    menu
                },
            ))
        }
    }

    #[gpui::test]
    fn keyboard_opens_selects_and_dismisses_a_dropdown(cx: &mut TestAppContext) {
        cx.update(gpui_component::init);
        let opens = Rc::new(Cell::new(0));
        let selections = Rc::new(Cell::new(0));
        let (_, cx) = cx.add_window_view({
            let opens = opens.clone();
            let selections = selections.clone();
            move |window, cx| {
                let view = cx.new(|_| Fixture {
                    opens,
                    selections,
                    bounds: Rc::new(RefCell::new(vec![Bounds::default()])),
                });
                Root::new(view, window, cx)
            }
        });
        let trigger_focus = cx.update(|window, cx| {
            window.activate_window();
            window.draw(cx).clear(cx);
            window.focus_next(cx);
            window.focused(cx).unwrap()
        });
        cx.simulate_keystrokes("space");
        cx.run_until_parked();
        assert_eq!(opens.get(), 1);
        cx.simulate_keystrokes("down enter");
        cx.run_until_parked();
        assert_eq!(selections.get(), 1);
        cx.update(|window, _| assert!(trigger_focus.is_focused(window)));
        cx.simulate_keystrokes("enter");
        cx.run_until_parked();
        assert_eq!(opens.get(), 2);
        cx.simulate_keystrokes("escape");
        cx.run_until_parked();
        cx.update(|window, _| assert!(trigger_focus.is_focused(window)));
    }

    #[gpui::test]
    fn long_dropdowns_reveal_keyboard_selection_and_restore_focus(cx: &mut TestAppContext) {
        cx.update(gpui_component::init);
        let opens = Rc::new(Cell::new(0));
        let selections = Rc::new(Cell::new(0));
        let bounds = Rc::new(RefCell::new(vec![Bounds::default(); 40]));
        let (_, cx) = cx.add_window_view({
            let selections = selections.clone();
            let bounds = bounds.clone();
            move |window, cx| {
                let view = cx.new(|_| Fixture {
                    opens,
                    selections,
                    bounds,
                });
                Root::new(view, window, cx)
            }
        });
        cx.simulate_resize(gpui::size(px(960.), px(640.)));
        let trigger = cx.update(|window, cx| {
            assert_eq!(window.viewport_size(), gpui::size(px(960.), px(640.)));
            window.activate_window();
            window.draw(cx).clear(cx);
            window.focus_next(cx);
            window.focused(cx).unwrap()
        });
        cx.simulate_keystrokes("space");
        cx.simulate_keystrokes(&vec!["down"; 40].join(" "));
        cx.update(|window, cx| {
            window.draw(cx).clear(cx);
            window.draw(cx).clear(cx);
            let last = bounds.borrow()[39];
            assert!(
                last.top() >= px(0.) && last.bottom() <= window.viewport_size().height,
                "{last:?}"
            );
        });
        cx.simulate_keystrokes(&vec!["up"; 39].join(" "));
        cx.update(|window, cx| {
            window.draw(cx).clear(cx);
            window.draw(cx).clear(cx);
            let first = bounds.borrow()[0];
            assert!(
                first.top() >= px(0.) && first.bottom() <= window.viewport_size().height,
                "{first:?}"
            );
        });
        cx.simulate_keystrokes(&vec!["down"; 39].join(" "));
        cx.simulate_keystrokes("enter");
        assert_eq!(selections.get(), 40);
        cx.update(|window, _| assert!(trigger.is_focused(window)));
    }
}
