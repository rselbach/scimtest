use rune::{Chord, KeyEvent, MenuItem, Shortcut, Tx};

use crate::workspace::Workspace;

const HELP_URL: &str = "https://github.com/rselbach/scimtest#readme";

fn key(spec: &str) -> Option<Shortcut> {
    match spec.parse() {
        Ok(shortcut) => Some(shortcut),
        Err(error) => {
            eprintln!("Menu shortcut {spec}: {error}");
            None
        }
    }
}

fn item(
    title: impl Into<String>,
    action: fn(&mut Workspace, &mut Tx),
    shortcut: &str,
) -> MenuItem<Workspace> {
    let item = MenuItem::new(title, action);
    match key(shortcut) {
        Some(shortcut) => item.key_equivalent(shortcut),
        None => item,
    }
}

fn help(_: &mut Workspace, tx: &mut Tx) {
    if let Err(error) = tx.open_url(HELP_URL) {
        eprintln!("Open help: {error}");
    }
}

fn release_notes(s: &mut Workspace, _: &mut Tx) {
    let (title, body) = crate::information::release_notes();
    crate::information::show_message(s.shell.as_ref(), title, body);
}

/// The menu bar's custom items; `update_label` names the updater's next step.
pub fn items(update_label: Option<String>) -> Vec<MenuItem<Workspace>> {
    let mut items = vec![
        item("Save", |s, _| s.save_shortcut(), "super+s").menu("File"),
        item("Refresh", |s, _| s.refresh(), "super+r").menu("View"),
        item("Search Directory", |s, _| s.focus_search(), "super+f").menu("View"),
        MenuItem::new("Zoom", |_, tx| tx.toggle_maximized()).menu("Window"),
        MenuItem::new("What's New in scimtest", release_notes).menu("Help"),
    ];
    if let Some(label) = update_label {
        items.push(
            MenuItem::new(label, |s: &mut Workspace, _| s.update_action())
                .id("update")
                .menu("Help"),
        );
    }
    items.extend([
        MenuItem::separator().menu("Help"),
        item("scimtest Help", help, "super+shift+slash").menu("Help"),
    ]);
    items
}

impl Workspace {
    /// Rebuilds the menu bar, whose updater item names the updater's state.
    pub(crate) fn refresh_menus(&self) {
        let Some(shell) = &self.shell else {
            return;
        };
        let label = self.updates.available().then(|| self.updates.menu_label());
        if let Err(error) = shell.app.set_menu(items(label)) {
            eprintln!("Update menus: {error}");
        }
    }
}

/// Window shortcuts for platforms without a native menu bar to carry them.
pub fn on_key(s: &mut Workspace, event: &KeyEvent, tx: &mut Tx) -> bool {
    if cfg!(target_os = "macos") {
        return false;
    }
    let matches = |spec: &str| Chord::parse(spec).is_ok_and(|chord| chord.matches_tx(event, tx));
    if matches("mod+q") {
        tx.quit();
    } else if matches("mod+w") {
        tx.close_window();
    } else if matches("mod+s") {
        s.save_shortcut();
    } else if matches("mod+r") {
        s.refresh();
    } else if matches("mod+f") {
        s.focus_search();
    } else if matches("mod+shift+/") {
        help(s, tx);
    } else {
        return false;
    }
    true
}
