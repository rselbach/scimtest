use gpui::{App, KeyBinding, Menu, MenuItem, OsAction, SystemMenuType, actions};
use gpui_component::input;

actions!(
    scimtest,
    [
        Quit,
        About,
        Help,
        ReleaseNotes,
        Hide,
        HideOthers,
        ShowAll,
        CloseWindow,
        Minimize,
        Zoom,
        FullScreen,
        BringToFront,
        Refresh,
        SearchDirectory,
        Save,
        Update,
    ]
);

pub fn install(updates: gpui::Entity<crate::updates::Controller>, cx: &mut App) {
    if updates.read(cx).available() {
        cx.on_action(move |_: &Update, cx| updates.update(cx, |updates, cx| updates.action(cx)));
    }
    cx.on_action(|_: &Quit, cx| cx.quit());
    cx.on_action(|_: &Hide, cx| cx.hide());
    cx.on_action(|_: &HideOthers, cx| cx.hide_other_apps());
    cx.on_action(|_: &ShowAll, cx| cx.unhide_other_apps());
    cx.on_action(|_: &Help, cx| cx.open_url("https://github.com/rselbach/scimtest#readme"));
    cx.on_action(|_: &About, cx| crate::information::show_about(cx));
    cx.on_action(|_: &ReleaseNotes, cx| crate::information::show_release_notes(cx));
    cx.on_action(|_: &CloseWindow, cx| {
        if let Some(window) = cx.active_window() {
            cx.defer(move |cx| {
                let _ = window.update(cx, |_, window, _| window.remove_window());
            });
        }
    });
    cx.on_action(|_: &Minimize, cx| {
        if let Some(window) = cx.active_window() {
            cx.defer(move |cx| {
                let _ = window.update(cx, |_, window, _| window.minimize_window());
            });
        }
    });
    cx.on_action(|_: &Zoom, cx| {
        if let Some(window) = cx.active_window() {
            cx.defer(move |cx| {
                let _ = window.update(cx, |_, window, _| window.zoom_window());
            });
        }
    });
    cx.on_action(|_: &FullScreen, cx| {
        if let Some(window) = cx.active_window() {
            cx.defer(move |cx| {
                let _ = window.update(cx, |_, window, _| window.toggle_fullscreen());
            });
        }
    });
    cx.on_action(|_: &BringToFront, cx| {
        for window in cx.windows() {
            cx.defer(move |cx| {
                let _ = window.update(cx, |_, window, _| window.activate_window());
            });
        }
        cx.activate(true);
    });
    let [
        quit_key,
        close_key,
        refresh_key,
        find_key,
        save_key,
        help_key,
    ] = if cfg!(target_os = "macos") {
        ["cmd-q", "cmd-w", "cmd-r", "cmd-f", "cmd-s", "cmd-shift-/"]
    } else {
        [
            "ctrl-q",
            "ctrl-w",
            "ctrl-r",
            "ctrl-f",
            "ctrl-s",
            "ctrl-shift-/",
        ]
    };
    cx.bind_keys([
        KeyBinding::new(quit_key, Quit, None),
        KeyBinding::new(close_key, CloseWindow, None),
        KeyBinding::new(refresh_key, Refresh, None),
        KeyBinding::new(find_key, SearchDirectory, None),
        KeyBinding::new(save_key, Save, None),
        KeyBinding::new(help_key, Help, None),
    ]);
    if cfg!(target_os = "macos") {
        cx.bind_keys([
            KeyBinding::new("cmd-h", Hide, None),
            KeyBinding::new("cmd-alt-h", HideOthers, None),
            KeyBinding::new("cmd-m", Minimize, None),
            KeyBinding::new("ctrl-cmd-f", FullScreen, None),
        ]);
    }
    refresh(cx, "Check for Updates…");
}

pub fn refresh(cx: &mut App, update_label: &str) {
    cx.set_menus(vec![
        Menu {
            name: "scimtest".into(),
            disabled: false,
            items: vec![
                MenuItem::action("About scimtest", About),
                MenuItem::action(update_label.to_owned(), Update),
                MenuItem::separator(),
                MenuItem::os_submenu("Services", SystemMenuType::Services),
                MenuItem::separator(),
                MenuItem::action("Hide scimtest", Hide),
                MenuItem::action("Hide Others", HideOthers),
                MenuItem::action("Show All", ShowAll),
                MenuItem::separator(),
                MenuItem::action("Quit scimtest", Quit),
            ],
        },
        Menu {
            name: "File".into(),
            disabled: false,
            items: vec![
                MenuItem::action("Save", Save),
                MenuItem::action("Close Window", CloseWindow),
            ],
        },
        Menu {
            name: "Edit".into(),
            disabled: false,
            items: vec![
                MenuItem::os_action("Undo", input::Undo, OsAction::Undo),
                MenuItem::os_action("Redo", input::Redo, OsAction::Redo),
                MenuItem::separator(),
                MenuItem::os_action("Cut", input::Cut, OsAction::Cut),
                MenuItem::os_action("Copy", input::Copy, OsAction::Copy),
                MenuItem::os_action("Paste", input::Paste, OsAction::Paste),
                MenuItem::action("Delete", input::Delete),
                MenuItem::os_action("Select All", input::SelectAll, OsAction::SelectAll),
                MenuItem::separator(),
                MenuItem::action("Emoji & Symbols", input::ShowCharacterPalette),
            ],
        },
        Menu {
            name: "View".into(),
            disabled: false,
            items: vec![
                MenuItem::action("Refresh", Refresh),
                MenuItem::action("Search Directory", SearchDirectory),
                MenuItem::separator(),
                MenuItem::action("Toggle Full Screen", FullScreen),
            ],
        },
        Menu {
            name: "Window".into(),
            disabled: false,
            items: vec![
                MenuItem::action("Minimize", Minimize),
                MenuItem::action("Zoom", Zoom),
                MenuItem::separator(),
                MenuItem::action("Bring All to Front", BringToFront),
            ],
        },
        Menu {
            name: "Help".into(),
            disabled: false,
            items: vec![
                MenuItem::action("What's New in scimtest", ReleaseNotes),
                MenuItem::separator(),
                MenuItem::action("scimtest Help", Help),
            ],
        },
    ]);
}
