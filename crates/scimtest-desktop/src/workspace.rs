mod account;
mod backups;
mod connection;
mod dismissal;
mod editor;
mod environment;
mod faults;
mod lifecycle;
mod oidc;
mod resilience;
mod rows;
mod saml;
mod scim;
mod table;
#[cfg(test)]
mod tests;
mod tools;
mod traffic;
pub(crate) mod view;

use std::{collections::BTreeSet, future::Future, sync::Arc};

use rune::{TextEdit, Tx};
use scimtest_core::{Error, Store, configuration::GlobalConfigPatch, model::*};

pub use view::view;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Tab {
    Users,
    Groups,
    Environments,
    Oidc,
    Saml,
    Scim,
    Traffic,
    Resilience,
    Lifecycle,
}

pub enum Editor {
    Lifecycle(lifecycle::Form),
    Faults(faults::Form),
    Environment {
        id: Option<String>,
        name: TextEdit,
        slug: TextEdit,
        settings: Box<environment::EnvironmentForm>,
    },
    User {
        id: Option<String>,
        fields: Box<[TextEdit; 9]>,
        active: bool,
        manager: String,
        original_manager: String,
        attributes: TextEdit,
    },
    Group {
        id: Option<String>,
        name: TextEdit,
        search: TextEdit,
        members: Vec<String>,
    },
    Delete {
        target: DeleteTarget,
        id: String,
        name: String,
    },
    Tools {
        count: TextEdit,
        domain: TextEdit,
    },
    Idp {
        base_url: TextEdit,
        trust_proxy: bool,
    },
    ConfirmTool {
        action: &'static str,
    },
    History {
        noun: &'static str,
        name: String,
        entries: Vec<OperationLog>,
        expanded: BTreeSet<usize>,
    },
    BulkDelete {
        target: DeleteTarget,
        ids: Vec<String>,
    },
    RestoreBackup {
        backup: Box<scimtest_core::backup::StateBackup>,
    },
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DeleteTarget {
    Environment,
    User,
    Group,
}

/// A change to the workspace made on the UI thread; true when it changed what shows.
pub type Update = Box<dyn FnOnce(&mut Workspace, &mut Tx) -> bool + Send>;

/// Hands background results to the UI thread: the app's handle while it runs, or a channel
/// a test drains.
#[derive(Clone)]
pub struct Lander(Arc<dyn Fn(Update) + Send + Sync>);

impl Lander {
    pub fn new(land: impl Fn(Update) + Send + Sync + 'static) -> Self {
        Self(Arc::new(land))
    }

    pub fn send(&self, update: impl FnOnce(&mut Workspace, &mut Tx) -> bool + Send + 'static) {
        (self.0)(Box::new(update));
    }
}

/// What the workspace needs from the process that hosts it.
pub struct Services {
    pub store: Store,
    pub identity: scimtest_core::oidc::Identity,
    pub scim: scimtest_core::scim::Service,
    pub tunnel: scimtest_core::tunnel::Service,
    pub executor: tokio::runtime::Handle,
    pub api_url: String,
    pub updates: crate::updates::Controller,
    pub lander: Lander,
    pub shell: Option<crate::Shell>,
}

pub struct Workspace {
    pub(crate) lander: Lander,
    pub(crate) shell: Option<crate::Shell>,
    pub(crate) updates: crate::updates::Controller,
    store: Store,
    identity: scimtest_core::oidc::Identity,
    scim_service: scimtest_core::scim::Service,
    tunnel_service: scimtest_core::tunnel::Service,
    tunnel_snapshot: scimtest_core::tunnel::Snapshot,
    account_open: bool,
    account_busy: bool,
    scim_view: scim::Inspector,
    scim_refresh_pending: bool,
    scim_refreshing: bool,
    identity_refresh_pending: bool,
    identity_refreshing: bool,
    executor: tokio::runtime::Handle,
    oidc: oidc::Inspector,
    saml: saml::Inspector,
    traffic: traffic::Inspector,
    resilience: resilience::Inspector,
    lifecycle: lifecycle::Inspector,
    directories: Vec<Directory>,
    selected: Option<String>,
    tab: Tab,
    editor: Option<Editor>,
    editor_dirty: bool,
    discarding: bool,
    busy: bool,
    message: String,
    failed: bool,
    api_url: String,
    search: TextEdit,
    status_filter: &'static str,
    selected_rows: BTreeSet<String>,
    page: usize,
    page_size: usize,
    sort_descending: bool,
    disclosures: BTreeSet<&'static str>,
    /// The dropdown menu that is open, by key.
    open_menu: Option<String>,
    /// Edits land here when a field's editor closed before its handler ran.
    scratch: TextEdit,
    app_icon: Option<rune::Image>,
}

fn edit(value: &str) -> TextEdit {
    TextEdit::new(value)
}

impl Workspace {
    pub fn new(services: Services) -> Self {
        let Services {
            store,
            identity,
            scim,
            tunnel,
            executor,
            api_url,
            updates,
            lander,
            shell,
        } = services;
        let tunnel_snapshot =
            tunnel
                .snapshot()
                .unwrap_or_else(|error| scimtest_core::tunnel::Snapshot {
                    error: error.to_string(),
                    ..Default::default()
                });
        let (directories, failure) = match store.snapshot() {
            Ok(directories) => (directories, None),
            Err(error) => (Vec::new(), Some(error.to_string())),
        };
        let selected = directories
            .first()
            .map(|directory| directory.environment.id.clone());
        let mut view = Self {
            lander,
            shell,
            updates,
            store,
            identity,
            scim_service: scim,
            tunnel_service: tunnel,
            tunnel_snapshot,
            account_open: false,
            account_busy: false,
            scim_view: scim::Inspector::default(),
            scim_refresh_pending: false,
            scim_refreshing: false,
            identity_refresh_pending: false,
            identity_refreshing: false,
            executor,
            oidc: oidc::Inspector::default(),
            saml: saml::Inspector::default(),
            traffic: traffic::Inspector::default(),
            resilience: resilience::Inspector::default(),
            lifecycle: lifecycle::Inspector::default(),
            directories,
            selected,
            tab: Tab::Users,
            editor: None,
            editor_dirty: false,
            discarding: false,
            busy: false,
            message: String::new(),
            failed: false,
            api_url,
            search: TextEdit::new(""),
            status_filter: "All",
            selected_rows: BTreeSet::new(),
            page: 0,
            page_size: 15,
            sort_descending: false,
            disclosures: BTreeSet::new(),
            open_menu: None,
            scratch: TextEdit::new(""),
            app_icon: None,
        };
        if let Some(failure) = failure {
            view.message = failure;
            view.failed = true;
        }
        view.watch();
        if view.selected.is_none() {
            view.edit_environment(None);
        }
        view
    }

    /// Runs once the window can wake the app: loads the images the view draws.
    pub fn setup(&mut self, waker: rune::Waker) {
        let images = rune::ImageCache::new(waker);
        self.app_icon = Some(images.load(&include_bytes!("../assets/app-icon.png")[..]));
    }

    /// Follows the services' change channels for as long as the workspace lives.
    fn watch(&self) {
        let lander = self.lander.clone();
        let tunnel = self.tunnel_service.clone();
        let mut tunnel_changes = tunnel.subscribe();
        self.executor.spawn(async move {
            while tunnel_changes.changed().await.is_ok() {
                let service = tunnel.clone();
                let result = tokio::task::spawn_blocking(move || service.snapshot()).await;
                lander.send(move |view, _| {
                    match result {
                        Ok(Ok(snapshot)) => {
                            view.tunnel_snapshot = snapshot;
                            if view.account_locked() {
                                view.editor = None;
                            }
                        }
                        Ok(Err(error)) => view.fail(error.to_string()),
                        Err(error) => view.fail(error.to_string()),
                    }
                    true
                });
            }
        });
        let lander = self.lander.clone();
        let store = self.store.clone();
        let mut changes = store.subscribe();
        self.executor.spawn(async move {
            while changes.changed().await.is_ok() {
                let store = store.clone();
                let result = tokio::task::spawn_blocking(move || store.snapshot()).await;
                lander.send(move |view, _| {
                    match result {
                        Ok(Ok(snapshot)) => view.replace_snapshot(snapshot),
                        Ok(Err(error)) => view.fail(error.to_string()),
                        Err(error) => view.fail(error.to_string()),
                    }
                    true
                });
            }
        });
        let lander = self.lander.clone();
        let mut identity_changes = self.identity.subscribe();
        self.executor.spawn(async move {
            while identity_changes.changed().await.is_ok() {
                lander.send(|view, _| {
                    if !view.tab.shows_identity() {
                        return false;
                    }
                    if view.busy {
                        view.identity_refresh_pending = true;
                    } else {
                        view.refresh_identity();
                    }
                    true
                });
            }
        });
        let lander = self.lander.clone();
        self.executor.spawn(async move {
            let mut ticks = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                ticks.tick().await;
                lander.send(|view, _| {
                    if !matches!(view.tab, Tab::Resilience | Tab::Lifecycle) || view.busy {
                        return false;
                    }
                    view.refresh_identity();
                    false
                });
            }
        });
        let lander = self.lander.clone();
        let mut traffic_changes = self.identity.diagnostics().subscribe();
        self.executor.spawn(async move {
            while traffic_changes.changed().await.is_ok() {
                lander.send(|view, _| {
                    if view.tab != Tab::Traffic {
                        return false;
                    }
                    view.refresh_traffic();
                    true
                });
            }
        });
        let lander = self.lander.clone();
        let mut scim_changes = self.scim_service.subscribe();
        self.executor.spawn(async move {
            while scim_changes.changed().await.is_ok() {
                lander.send(|view, _| {
                    if view.tab != Tab::Scim {
                        return false;
                    }
                    if view.busy {
                        view.scim_refresh_pending = true;
                    } else {
                        view.refresh_scim();
                    }
                    true
                });
            }
        });
    }

    /// Runs `work` on a blocking worker and hands its result to `land` on the UI thread.
    pub(crate) fn background<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
        land: impl FnOnce(&mut Self, T) + Send + 'static,
    ) {
        let lander = self.lander.clone();
        self.executor.spawn_blocking(move || {
            let value = work();
            lander.send(move |view, _| {
                land(view, value);
                true
            });
        });
    }

    pub(crate) fn spawn_future(&self, future: impl Future<Output = ()> + Send + 'static) {
        self.executor.spawn(future);
    }

    /// Runs `future` on the tokio runtime and hands its output to `land` on the UI thread.
    pub(crate) fn task<T: Send + 'static>(
        &self,
        future: impl Future<Output = T> + Send + 'static,
        land: impl FnOnce(&mut Self, T, &mut Tx) + Send + 'static,
    ) {
        let lander = self.lander.clone();
        self.executor.spawn(async move {
            let value = future.await;
            lander.send(move |view, tx| {
                land(view, value, tx);
                true
            });
        });
    }

    fn fail(&mut self, message: String) {
        self.message = message;
        self.failed = true;
    }

    fn directory(&self) -> Option<&Directory> {
        self.directories
            .iter()
            .find(|directory| Some(&directory.environment.id) == self.selected.as_ref())
    }

    fn replace_snapshot(&mut self, snapshot: Vec<Directory>) {
        if (self.selected.is_some() || !snapshot.is_empty())
            && !snapshot
                .iter()
                .any(|directory| Some(&directory.environment.id) == self.selected.as_ref())
        {
            self.selected = snapshot
                .first()
                .map(|directory| directory.environment.id.clone());
            self.editor = None;
        }
        self.directories = snapshot;
        let valid = self
            .directory()
            .map(|directory| match self.tab {
                Tab::Users => directory
                    .users
                    .iter()
                    .filter(|user| !user.deleted)
                    .map(|user| user.id.clone())
                    .collect::<BTreeSet<_>>(),
                Tab::Groups => directory
                    .groups
                    .iter()
                    .filter(|group| !group.deleted)
                    .map(|group| group.id.clone())
                    .collect(),
                Tab::Environments
                | Tab::Oidc
                | Tab::Saml
                | Tab::Scim
                | Tab::Traffic
                | Tab::Resilience
                | Tab::Lifecycle => BTreeSet::new(),
            })
            .unwrap_or_default();
        self.selected_rows.retain(|id| valid.contains(id));
    }

    fn command(
        &mut self,
        action: impl FnOnce(Store) -> Result<(String, Option<String>), Error> + Send + 'static,
    ) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.message.clear();
        let store = self.store.clone();
        self.background(
            move || {
                let (message, selection) = action(store.clone())?;
                Ok::<_, Error>((message, selection, store.snapshot()?))
            },
            |view, result| {
                view.busy = false;
                match result {
                    Ok((message, selection, snapshot)) => {
                        if let Some(selection) = selection {
                            view.selected = Some(selection);
                            view.page = 0;
                            view.status_filter = "All";
                            if view.tab == Tab::Environments {
                                view.tab = Tab::Users;
                            }
                        }
                        view.replace_snapshot(snapshot);
                        view.close_editor();
                        view.message = message;
                        view.failed = false;
                        view.selected_rows.clear();
                    }
                    Err(error) => view.fail(error.to_string()),
                }
            },
        );
    }

    /// Opens an editor in place of whatever editor was open, unchanged so far.
    fn open_editor(&mut self, editor: Editor) {
        self.editor = Some(editor);
        self.editor_dirty = false;
        self.discarding = false;
        self.open_menu = None;
        self.message.clear();
    }

    fn edit_environment(&mut self, environment: Option<&Environment>) {
        let settings = match environment::EnvironmentForm::new(environment) {
            Ok(settings) => settings,
            Err(error) => {
                self.fail(error.to_string());
                return;
            }
        };
        let mut name = edit(
            environment
                .map(|environment| environment.name.as_str())
                .unwrap_or_default(),
        );
        name.focused = true;
        self.open_editor(Editor::Environment {
            settings: Box::new(settings),
            id: environment.map(|environment| environment.id.clone()),
            name,
            slug: edit(
                environment
                    .map(|environment| environment.slug.as_str())
                    .unwrap_or_default(),
            ),
        });
    }

    fn edit_user(&mut self, user: Option<&User>) {
        let fields = user.map(|user| user.fields.clone()).unwrap_or_default();
        let mut edits = [
            &fields.given_name,
            &fields.family_name,
            &fields.email,
            &fields.username,
            &fields.employee_number,
            &fields.cost_center,
            &fields.organization,
            &fields.division,
            &fields.department,
        ]
        .map(|value| edit(value));
        edits[3].focused = true;
        self.open_editor(Editor::User {
            id: user.map(|user| user.id.clone()),
            fields: Box::new(edits),
            active: user.is_none_or(|user| user.fields.active),
            manager: fields.manager_id.clone(),
            original_manager: fields.manager_id.clone(),
            attributes: edit(&scimtest_core::format_custom_attributes(&fields.attributes)),
        });
    }

    fn edit_group(&mut self, group: Option<&Group>) {
        let mut name = edit(
            group
                .map(|group| group.fields.display_name.as_str())
                .unwrap_or_default(),
        );
        name.focused = true;
        self.open_editor(Editor::Group {
            id: group.map(|group| group.id.clone()),
            name,
            search: edit(""),
            members: group
                .map(|group| group.fields.member_ids.clone())
                .unwrap_or_default(),
        });
    }

    fn select_environment(&mut self, id: String) {
        self.selected = Some(id);
        let enabled = self.directory().is_some_and(|directory| match self.tab {
            Tab::Scim => directory.environment.settings.scim_enabled,
            Tab::Oidc => directory.environment.settings.supports_oidc(),
            Tab::Saml => directory.environment.settings.supports_saml(),
            Tab::Resilience => {
                directory.environment.settings.supports_oidc()
                    || directory.environment.settings.supports_saml()
            }
            _ => true,
        });
        if !enabled {
            self.tab = Tab::Users;
        }
        self.oidc = Default::default();
        self.saml = Default::default();
        self.scim_view = Default::default();
        self.resilience = Default::default();
        self.lifecycle = Default::default();
        if self.tab == Tab::Scim {
            self.refresh_scim();
        }
        if self.tab.shows_identity() {
            self.refresh_identity();
        }
        self.selected_rows.clear();
        self.page = 0;
        self.status_filter = "All";
        self.editor = None;
        self.message.clear();
    }

    fn show_tab(&mut self, tab: Tab) {
        if self.busy {
            return;
        }
        self.tab = tab;
        self.selected_rows.clear();
        self.page = 0;
        self.status_filter = "All";
        self.editor = None;
        self.message.clear();
        if tab == Tab::Scim {
            self.refresh_scim();
        }
        if tab.shows_identity() {
            self.refresh_identity();
        }
        if tab == Tab::Traffic {
            self.refresh_traffic();
        }
    }

    /// Focuses the directory search, as ⌘F does.
    pub(crate) fn focus_search(&mut self) {
        if !self.busy
            && !self.account_locked()
            && !self.account_open
            && self.editor.is_none()
            && matches!(self.tab, Tab::Users | Tab::Groups | Tab::Environments)
        {
            self.search.focused = true;
        }
    }

    /// Saves the open editor, as ⌘S does.
    pub(crate) fn save_shortcut(&mut self) {
        if !self.busy && !self.account_locked() && !self.account_open && self.editor.is_some() {
            self.save();
        }
    }

    /// Refreshes the current page, as ⌘R does.
    pub(crate) fn refresh(&mut self) {
        if self.busy || self.account_locked() || self.account_open || self.editor.is_some() {
            return;
        }
        match self.tab {
            Tab::Scim => self.refresh_scim(),
            Tab::Traffic => self.refresh_traffic(),
            Tab::Oidc | Tab::Saml | Tab::Resilience | Tab::Lifecycle => self.refresh_identity(),
            _ => self.command(|_| Ok(("Refreshed".into(), None))),
        }
    }

    fn save(&mut self) {
        if self.discarding {
            return;
        }
        let blocked = match &self.editor {
            Some(Editor::Environment { name, settings, .. }) => settings.first_error(name),
            _ => None,
        };
        if let Some((section, message)) = blocked {
            self.show_environment_error(section, message);
            return;
        }
        let environment = self.selected.clone().unwrap_or_default();
        match &self.editor {
            Some(Editor::Lifecycle(_)) => self.save_lifecycle(),
            Some(Editor::Faults(form)) => {
                let faults = match form.values() {
                    Ok(faults) => faults,
                    Err(error) => {
                        self.fail(error.to_string());
                        return;
                    }
                };
                self.identity_command(move |identity, id| {
                    identity.arm_faults(&id, faults)?;
                    Ok("Custom faults armed for the next matching flow".into())
                });
            }
            Some(Editor::Environment {
                id,
                name,
                slug,
                settings,
            }) => {
                let settings = match settings.patch() {
                    Ok(settings) => settings,
                    Err(error) => {
                        self.fail(error.to_string());
                        return;
                    }
                };
                let id = id.clone();
                let name = name.text.clone();
                let slug = slug.text.clone();
                self.command(move |store| {
                    let environment = match id {
                        Some(id) => store.update_environment(
                            &id,
                            EnvironmentPatch {
                                name: Some(name),
                                slug: Some(slug),
                                settings,
                            },
                        )?,
                        None => store.create_environment(EnvironmentInput {
                            name,
                            slug,
                            settings,
                        })?,
                    };
                    Ok(("Environment saved".into(), Some(environment.id)))
                });
            }
            Some(Editor::User {
                id,
                fields,
                active,
                manager,
                original_manager,
                attributes,
            }) => {
                let id = id.clone();
                let [
                    given_name,
                    family_name,
                    email,
                    username,
                    employee_number,
                    cost_center,
                    organization,
                    division,
                    department,
                ] = fields.each_ref().map(|field| field.text.clone());
                let active = *active;
                let manager = manager.clone();
                let manager_changed = &manager != original_manager;
                let attributes = attributes.text.clone();
                self.command(move |store| {
                    let attributes = scimtest_core::parse_custom_attributes(&attributes)?;
                    match id {
                        Some(id) => {
                            store.update_user(
                                &environment,
                                &id,
                                UserPatch {
                                    given_name: Some(given_name),
                                    family_name: Some(family_name),
                                    email: Some(email),
                                    username: Some(username),
                                    active: Some(active),
                                    employee_number: Some(employee_number),
                                    cost_center: Some(cost_center),
                                    organization: Some(organization),
                                    division: Some(division),
                                    department: Some(department),
                                    manager_id: manager_changed.then_some(manager),
                                    attributes: Some(attributes),
                                },
                            )?;
                        }
                        None => {
                            store.create_user(
                                &environment,
                                UserInput {
                                    given_name,
                                    family_name,
                                    email,
                                    username,
                                    active,
                                    employee_number,
                                    cost_center,
                                    organization,
                                    division,
                                    department,
                                    manager_id: manager,
                                    attributes,
                                },
                            )?;
                        }
                    }
                    Ok(("User saved".into(), None))
                });
            }
            Some(Editor::Group {
                id, name, members, ..
            }) => {
                let id = id.clone();
                let display_name = name.text.clone();
                let member_ids = members.clone();
                self.command(move |store| {
                    match id {
                        Some(id) => {
                            store.update_group(
                                &environment,
                                &id,
                                GroupPatch {
                                    display_name: Some(display_name),
                                    member_ids: Some(member_ids),
                                },
                            )?;
                        }
                        None => {
                            store.create_group(
                                &environment,
                                GroupInput {
                                    display_name,
                                    member_ids,
                                },
                            )?;
                        }
                    }
                    Ok(("Group saved".into(), None))
                });
            }
            Some(Editor::Delete { target, id, .. }) => {
                let target = *target;
                let id = id.clone();
                self.command(move |store| {
                    match target {
                        DeleteTarget::Environment => store.delete_environment(&id)?,
                        DeleteTarget::User => store.delete_user(&environment, &id)?,
                        DeleteTarget::Group => store.delete_group(&environment, &id)?,
                    }
                    Ok(("Deleted".into(), None))
                });
            }
            Some(Editor::BulkDelete { target, ids }) => {
                let target = *target;
                let ids = ids.clone();
                self.command(move |store| {
                    let count = match target {
                        DeleteTarget::User => store.delete_users(&environment, &ids)?,
                        DeleteTarget::Group => store.delete_groups(&environment, &ids)?,
                        DeleteTarget::Environment => {
                            return Err(Error::Validation("Select users or groups".into()));
                        }
                    };
                    Ok((format!("Deleted {count} entries"), None))
                });
            }
            Some(Editor::RestoreBackup { backup }) => {
                let backup = *backup.clone();
                self.command(move |store| {
                    let safety = store.restore_backup(&environment, backup)?;
                    Ok((
                        format!(
                            "Backup restored; previous state saved to {}",
                            safety.display()
                        ),
                        None,
                    ))
                });
            }
            Some(Editor::Idp {
                base_url,
                trust_proxy,
            }) => {
                let base_url = base_url.text.clone();
                let trust_proxy = *trust_proxy;
                self.command(move |store| {
                    store.update_global_config(&GlobalConfigPatch {
                        idp_base_url: Some(base_url),
                        trust_forwarded_headers: Some(trust_proxy),
                        ..Default::default()
                    })?;
                    Ok(("IDP and tunnel settings saved".into(), None))
                });
            }
            Some(Editor::ConfirmTool { action }) => {
                let action = *action;
                self.command(move |store| {
                    let result = if action == "clear-local" {
                        store.clear_directory(&environment)?
                    } else {
                        store.delete_all_users(&environment)?
                    };
                    Ok((
                        format!(
                            "Changed {} users and {} groups",
                            result.users_changed, result.groups_changed
                        ),
                        None,
                    ))
                });
            }
            Some(Editor::History { .. } | Editor::Tools { .. }) | None => {}
        }
    }
}

impl Tab {
    /// Pages that show the identity provider's state.
    fn shows_identity(self) -> bool {
        matches!(
            self,
            Self::Oidc | Self::Saml | Self::Resilience | Self::Lifecycle
        )
    }
}

/// A named state for Rune's headless `--snap --scene` runs.
type Scene = (&'static str, fn(&mut Workspace));

pub const SCENES: &[Scene] = &[
    ("groups", |s| s.show_tab(Tab::Groups)),
    ("environments", |s| s.show_tab(Tab::Environments)),
    ("oidc", |s| s.show_tab(Tab::Oidc)),
    ("saml", |s| s.show_tab(Tab::Saml)),
    ("scim", |s| s.show_tab(Tab::Scim)),
    ("traffic", |s| s.show_tab(Tab::Traffic)),
    ("traffic-sample", |s| s.show_traffic_sample()),
    ("resilience", |s| s.show_tab(Tab::Resilience)),
    ("lifecycle", |s| s.show_tab(Tab::Lifecycle)),
    ("account", |s| s.account_open = true),
    ("user-editor", |s| {
        let user = s.visible_users().into_iter().next();
        s.edit_user(user.as_ref());
    }),
    ("new-user", |s| s.edit_user(None)),
    ("group-editor", |s| {
        s.tab = Tab::Groups;
        let group = s.visible_groups().into_iter().next();
        s.edit_group(group.as_ref());
    }),
    ("environment-editor", |s| {
        let environment = s.directory().map(|directory| directory.environment.clone());
        s.edit_environment(environment.as_ref());
    }),
    ("new-environment", |s| s.edit_environment(None)),
    ("environment-oidc", |s| {
        let environment = s.directory().map(|directory| directory.environment.clone());
        s.edit_environment(environment.as_ref());
        s.disclosures.insert("oidc-claims");
        s.set_environment_step(1);
    }),
    ("environment-saml", |s| {
        let environment = s.directory().map(|directory| directory.environment.clone());
        s.edit_environment(environment.as_ref());
        s.disclosures.extend(["saml-signing", "saml-mappings"]);
        s.set_environment_step(2);
    }),
    ("environment-review", |s| {
        let environment = s.directory().map(|directory| directory.environment.clone());
        s.edit_environment(environment.as_ref());
        s.set_environment_step(4);
    }),
    ("tools", |s| s.open_tools()),
    ("idp", |s| s.open_idp()),
];
