mod account;
mod backups;
mod connection;
mod dismissal;
mod editor;
mod environment;
mod faults;
mod lifecycle;
mod modals;
mod oidc;
mod resilience;
mod row_focus;
mod rows;
mod saml;
mod scim;
mod table;
#[cfg(test)]
mod tests;
mod tools;
mod traffic;
mod view;

use std::collections::BTreeSet;

use gpui::{AppContext, Context, Entity, Window};
use gpui_component::{
    Theme,
    input::{InputEvent, InputState, TextareaState},
};
use scimtest_core::{Error, Store, configuration::GlobalConfigPatch, model::*};

#[derive(Clone, Copy, PartialEq)]
enum Tab {
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

enum Editor {
    Lifecycle(lifecycle::Form),
    Faults(faults::Form),
    Environment {
        id: Option<String>,
        name: Entity<InputState>,
        slug: Entity<InputState>,
        settings: environment::EnvironmentForm,
    },
    User {
        id: Option<String>,
        fields: Box<[Entity<InputState>; 9]>,
        active: bool,
        manager: String,
        original_manager: String,
        attributes: Entity<TextareaState>,
    },
    Group {
        id: Option<String>,
        name: Entity<InputState>,
        search: Entity<InputState>,
        members: Vec<String>,
    },
    Delete {
        target: DeleteTarget,
        id: String,
        name: String,
    },
    Tools {
        count: Entity<InputState>,
        domain: Entity<InputState>,
    },
    Idp {
        base_url: Entity<InputState>,
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

#[derive(Clone, Copy)]
enum DeleteTarget {
    Environment,
    User,
    Group,
}

pub struct Workspace {
    focus: gpui::FocusHandle,
    editor_focus: gpui::FocusHandle,
    editor_kind: Option<(
        std::mem::Discriminant<Editor>,
        Option<gpui_component::input::AnyInputState>,
    )>,
    editor_dirty: bool,
    editor_subscriptions: Vec<gpui::Subscription>,
    discard_focus: gpui::FocusHandle,
    discard_accept_focus: gpui::FocusHandle,
    discard_return_focus: Option<gpui::FocusHandle>,
    previous_focus: Option<gpui::FocusHandle>,
    return_focus: Option<gpui::FocusHandle>,
    account_focus: gpui::FocusHandle,
    account_button_focus: gpui::FocusHandle,
    account_visible: bool,
    account_return_focus: Option<gpui::FocusHandle>,
    updates: Entity<crate::updates::Controller>,
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
    busy: bool,
    message: String,
    status_revision: usize,
    failed: bool,
    api_url: String,
    table_scroll: gpui::ScrollHandle,
    member_scroll: gpui::ScrollHandle,
    search: Entity<InputState>,
    status_filter: &'static str,
    selected_rows: BTreeSet<String>,
    page: usize,
    page_size: usize,
    sort_descending: bool,
    disclosures: BTreeSet<&'static str>,
}

fn input(
    value: &str,
    placeholder: &str,
    window: &mut Window,
    cx: &mut Context<Workspace>,
) -> Entity<InputState> {
    cx.new(|cx| {
        let mut input = InputState::new(window, cx).placeholder(placeholder.to_owned());
        input.set_value(value.to_owned(), window, cx);
        input
    })
}

impl Workspace {
    pub fn install_shortcuts(
        view: &Entity<Self>,
        window: gpui::AnyWindowHandle,
        cx: &mut gpui::App,
    ) {
        let search = view.downgrade();
        cx.on_action(move |_: &crate::menus::SearchDirectory, cx| {
            let Some(window) = cx
                .active_window()
                .filter(|active| active.window_id() == window.window_id())
            else {
                return;
            };
            let search = search.clone();
            cx.defer(move |cx| {
                let outcome = window.update(cx, |_, window, cx| {
                    search.update(cx, |view, cx| {
                        if !view.busy
                            && !view.account_locked()
                            && !view.account_open
                            && view.editor.is_none()
                            && matches!(view.tab, Tab::Users | Tab::Groups | Tab::Environments)
                        {
                            view.search.update(cx, |input, cx| input.focus(window, cx));
                        }
                    })
                });
                if let Err(error) = outcome.and_then(|result| result) {
                    eprintln!("Focus directory search: {error:#}");
                }
            });
        });
        let save = view.downgrade();
        cx.on_action(move |_: &crate::menus::Save, cx| {
            if !cx
                .active_window()
                .is_some_and(|active| active.window_id() == window.window_id())
            {
                return;
            }
            let _ = save.update(cx, |view, cx| {
                if !view.busy
                    && !view.account_locked()
                    && !view.account_open
                    && view.editor.is_some()
                {
                    view.save(cx);
                }
            });
        });
        let refresh = view.downgrade();
        cx.on_action(move |_: &crate::menus::Refresh, cx| {
            if !cx
                .active_window()
                .is_some_and(|active| active.window_id() == window.window_id())
            {
                return;
            }
            let _ = refresh.update(cx, |view, cx| {
                if view.busy || view.account_locked() || view.account_open || view.editor.is_some()
                {
                    return;
                }
                match view.tab {
                    Tab::Scim => view.refresh_scim(cx),
                    Tab::Traffic => view.refresh_traffic(cx),
                    Tab::Oidc | Tab::Saml | Tab::Resilience | Tab::Lifecycle => {
                        view.refresh_identity(cx)
                    }
                    _ => view.command(|_| Ok(("Refreshed".into(), None)), cx),
                }
            });
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Store,
        identity: scimtest_core::oidc::Identity,
        scim_service: scimtest_core::scim::Service,
        tunnel_service: scimtest_core::tunnel::Service,
        executor: tokio::runtime::Handle,
        directories: Vec<Directory>,
        api_url: String,
        updates: Entity<crate::updates::Controller>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        cx.observe(&updates, |_, _, cx| cx.notify()).detach();
        cx.observe_window_appearance(window, |_, window, cx| {
            Theme::sync_system_appearance(Some(window), cx);
            crate::theme::apply(cx);
            cx.notify();
        })
        .detach();
        let tunnel_snapshot =
            tunnel_service
                .snapshot()
                .unwrap_or_else(|error| scimtest_core::tunnel::Snapshot {
                    error: error.to_string(),
                    ..Default::default()
                });
        let mut tunnel_changes = tunnel_service.subscribe();
        tunnel_changes.mark_changed();
        let observed_tunnel = tunnel_service.clone();
        cx.spawn(async move |view, cx| {
            while tunnel_changes.changed().await.is_ok() {
                let service = observed_tunnel.clone();
                let result = cx
                    .background_executor()
                    .spawn(async move { service.snapshot() })
                    .await;
                if view
                    .update(cx, |view, cx| {
                        match result {
                            Ok(snapshot) => {
                                view.tunnel_snapshot = snapshot;
                                if view.account_locked() {
                                    view.editor = None;
                                }
                            }
                            Err(error) => {
                                view.message = error.to_string();
                                view.failed = true;
                            }
                        }
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
        let selected = directories
            .first()
            .map(|directory| directory.environment.id.clone());
        let mut changes = store.subscribe();
        changes.mark_changed();
        let observed_store = store.clone();
        cx.spawn(async move |view, cx| {
            while changes.changed().await.is_ok() {
                let store = observed_store.clone();
                let result = cx
                    .background_executor()
                    .spawn(async move { store.snapshot() })
                    .await;
                if view
                    .update(cx, |view, cx| {
                        match result {
                            Ok(snapshot) => view.replace_snapshot(snapshot),
                            Err(error) => {
                                view.message = error.to_string();
                                view.failed = true;
                            }
                        }
                        cx.notify();
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
        let mut identity_changes = identity.subscribe();
        cx.spawn(async move |view, cx| {
            while identity_changes.changed().await.is_ok() {
                if view
                    .update(cx, |view, cx| {
                        if matches!(
                            view.tab,
                            Tab::Oidc | Tab::Saml | Tab::Resilience | Tab::Lifecycle
                        ) {
                            if view.busy {
                                view.identity_refresh_pending = true;
                            } else {
                                view.refresh_identity(cx);
                            }
                        }
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
        let mut traffic_changes = identity.diagnostics().subscribe();
        cx.spawn(async move |view, cx| {
            loop {
                cx.background_executor()
                    .timer(std::time::Duration::from_secs(1))
                    .await;
                if view
                    .update(cx, |view, cx| {
                        if matches!(view.tab, Tab::Resilience | Tab::Lifecycle) && !view.busy {
                            view.refresh_identity(cx);
                        }
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
        cx.spawn(async move |view, cx| {
            while traffic_changes.changed().await.is_ok() {
                if view
                    .update(cx, |view, cx| {
                        if view.tab == Tab::Traffic {
                            view.refresh_traffic(cx);
                        }
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
        let mut scim_changes = scim_service.subscribe();
        cx.spawn(async move |view, cx| {
            while scim_changes.changed().await.is_ok() {
                if view
                    .update(cx, |view, cx| {
                        if view.tab == Tab::Scim {
                            if view.busy {
                                view.scim_refresh_pending = true;
                            } else {
                                view.refresh_scim(cx);
                            }
                        }
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
        let search = input("", "name, username, email", window, cx);
        cx.subscribe(&search, |view, _, event: &InputEvent, cx| {
            if matches!(event, InputEvent::Change) {
                view.page = 0;
                view.table_scroll.set_offset(Default::default());
                cx.notify();
            }
        })
        .detach();
        let mut view = Self {
            focus: cx.focus_handle(),
            editor_focus: cx.focus_handle().tab_stop(false),
            editor_kind: None,
            editor_dirty: false,
            editor_subscriptions: Vec::new(),
            discard_focus: cx.focus_handle().tab_stop(false),
            discard_accept_focus: cx.focus_handle(),
            discard_return_focus: None,
            previous_focus: None,
            return_focus: None,
            account_focus: cx.focus_handle().tab_stop(false),
            account_button_focus: cx.focus_handle(),
            account_visible: false,
            account_return_focus: None,
            updates,
            store,
            identity,
            scim_service,
            tunnel_service,
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
            busy: false,
            message: String::new(),
            status_revision: 0,
            failed: false,
            api_url,
            table_scroll: gpui::ScrollHandle::default(),
            member_scroll: gpui::ScrollHandle::default(),
            search,
            status_filter: "All",
            selected_rows: BTreeSet::new(),
            page: 0,
            page_size: 15,
            sort_descending: false,
            disclosures: BTreeSet::new(),
        };
        if view.selected.is_none() {
            view.edit_environment(None, window, cx);
        } else {
            window.focus(&view.focus, cx);
        }
        view
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
        cx: &mut Context<Self>,
    ) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.message.clear();
        let store = self.store.clone();
        let task = cx.background_executor().spawn(async move {
            let (message, selection) = action(store.clone())?;
            Ok::<_, Error>((message, selection, store.snapshot()?))
        });
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.busy = false;
                view.status_revision = view.status_revision.wrapping_add(1);
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
                        view.editor = None;
                        view.message = message;
                        view.failed = false;
                        view.selected_rows.clear();
                    }
                    Err(error) => {
                        view.message = error.to_string();
                        view.failed = true;
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn edit_environment(
        &mut self,
        environment: Option<&Environment>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let settings = match environment::EnvironmentForm::new(environment, window, cx) {
            Ok(settings) => settings,
            Err(error) => {
                self.message = error.to_string();
                self.failed = true;
                cx.notify();
                return;
            }
        };
        self.editor = Some(Editor::Environment {
            settings,
            id: environment.map(|environment| environment.id.clone()),
            name: input(
                environment
                    .map(|environment| environment.name.as_str())
                    .unwrap_or_default(),
                "Greendale Portal",
                window,
                cx,
            ),
            slug: input(
                environment
                    .map(|environment| environment.slug.as_str())
                    .unwrap_or_default(),
                "Generated from the name",
                window,
                cx,
            ),
        });
        if let Some(Editor::Environment { name, .. }) = &self.editor {
            name.update(cx, |input, cx| input.focus(window, cx));
        }
        self.message.clear();
        cx.notify();
    }

    fn edit_user(&mut self, user: Option<&User>, window: &mut Window, cx: &mut Context<Self>) {
        let values = user.map(|user| {
            [
                &user.fields.given_name,
                &user.fields.family_name,
                &user.fields.email,
                &user.fields.username,
                &user.fields.employee_number,
                &user.fields.cost_center,
                &user.fields.organization,
                &user.fields.division,
                &user.fields.department,
            ]
        });
        let placeholders = [
            "Troy",
            "Barnes",
            "troy@greendale.edu",
            "Defaults to email",
            "GCC42",
            "Air conditioning",
            "Greendale Community College",
            "Annex",
            "Film Studies",
        ];
        let attributes = cx.new(|cx| {
            let mut state = TextareaState::new(window, cx)
                .auto_grow(3, 6)
                .placeholder("role=student");
            state.set_value(
                user.map(|user| scimtest_core::format_custom_attributes(&user.fields.attributes))
                    .unwrap_or_default(),
                window,
                cx,
            );
            state
        });
        self.editor = Some(Editor::User {
            id: user.map(|user| user.id.clone()),
            fields: Box::new(std::array::from_fn(|index| {
                input(
                    values
                        .map(|values| values[index].as_str())
                        .unwrap_or_default(),
                    placeholders[index],
                    window,
                    cx,
                )
            })),
            active: user.is_none_or(|user| user.fields.active),
            manager: user
                .map(|user| user.fields.manager_id.clone())
                .unwrap_or_default(),
            original_manager: user
                .map(|user| user.fields.manager_id.clone())
                .unwrap_or_default(),
            attributes,
        });
        if let Some(Editor::User { fields, .. }) = &self.editor {
            fields[3].update(cx, |input, cx| input.focus(window, cx));
        }
        self.message.clear();
        cx.notify();
    }

    fn edit_group(&mut self, group: Option<&Group>, window: &mut Window, cx: &mut Context<Self>) {
        self.editor = Some(Editor::Group {
            id: group.map(|group| group.id.clone()),
            name: input(
                group
                    .map(|group| group.fields.display_name.as_str())
                    .unwrap_or_default(),
                "Study Group",
                window,
                cx,
            ),
            search: input("", "Search users", window, cx),
            members: group
                .map(|group| group.fields.member_ids.clone())
                .unwrap_or_default(),
        });
        if let Some(Editor::Group { name, .. }) = &self.editor {
            name.update(cx, |input, cx| input.focus(window, cx));
        }
        self.message.clear();
        cx.notify();
    }

    fn select_environment(&mut self, id: String, cx: &mut Context<Self>) {
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
            self.refresh_scim(cx);
        }
        if matches!(
            self.tab,
            Tab::Oidc | Tab::Saml | Tab::Resilience | Tab::Lifecycle
        ) {
            self.refresh_identity(cx);
        }
        self.selected_rows.clear();
        self.page = 0;
        self.status_filter = "All";
        self.table_scroll.set_offset(Default::default());
        self.editor = None;
        self.message.clear();
        cx.notify();
    }

    fn save(&mut self, cx: &mut Context<Self>) {
        if self.discard_return_focus.is_some() {
            return;
        }
        self.status_revision = self.status_revision.wrapping_add(1);
        let blocked = match &self.editor {
            Some(Editor::Environment { name, settings, .. }) => settings.first_error(name, cx),
            _ => None,
        };
        if let Some((section, message)) = blocked {
            self.show_environment_error(section, message, cx);
            return;
        }
        let environment = self.selected.clone().unwrap_or_default();
        match &self.editor {
            Some(Editor::Lifecycle(_)) => self.save_lifecycle(cx),
            Some(Editor::Faults(form)) => {
                let faults = match form.values(cx) {
                    Ok(faults) => faults,
                    Err(error) => {
                        self.message = error.to_string();
                        self.failed = true;
                        cx.notify();
                        return;
                    }
                };
                self.identity_command(
                    move |identity, id| {
                        identity.arm_faults(&id, faults)?;
                        Ok("Custom faults armed for the next matching flow".into())
                    },
                    cx,
                );
            }
            Some(Editor::Environment {
                id,
                name,
                slug,
                settings,
            }) => {
                let settings = match settings.patch(cx) {
                    Ok(settings) => settings,
                    Err(error) => {
                        self.message = error.to_string();
                        self.failed = true;
                        cx.notify();
                        return;
                    }
                };
                let id = id.clone();
                let name = name.read(cx).value().to_string();
                let slug = slug.read(cx).value().to_string();
                self.command(
                    move |store| {
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
                    },
                    cx,
                );
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
                ] = fields
                    .each_ref()
                    .map(|input| input.read(cx).value().to_string());
                let active = *active;
                let manager = manager.clone();
                let manager_changed = &manager != original_manager;
                let attributes = attributes.read(cx).value().to_string();
                self.command(
                    move |store| {
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
                    },
                    cx,
                );
            }
            Some(Editor::Group {
                id, name, members, ..
            }) => {
                let id = id.clone();
                let display_name = name.read(cx).value().to_string();
                let member_ids = members.clone();
                self.command(
                    move |store| {
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
                    },
                    cx,
                );
            }
            Some(Editor::Delete { target, id, .. }) => {
                let target = *target;
                let id = id.clone();
                self.command(
                    move |store| {
                        match target {
                            DeleteTarget::Environment => store.delete_environment(&id)?,
                            DeleteTarget::User => store.delete_user(&environment, &id)?,
                            DeleteTarget::Group => store.delete_group(&environment, &id)?,
                        }
                        Ok(("Deleted".into(), None))
                    },
                    cx,
                );
            }
            Some(Editor::BulkDelete { target, ids }) => {
                let target = *target;
                let ids = ids.clone();
                self.command(
                    move |store| {
                        let count = match target {
                            DeleteTarget::User => store.delete_users(&environment, &ids)?,
                            DeleteTarget::Group => store.delete_groups(&environment, &ids)?,
                            DeleteTarget::Environment => {
                                return Err(Error::Validation("Select users or groups".into()));
                            }
                        };
                        Ok((format!("Deleted {count} entries"), None))
                    },
                    cx,
                );
            }
            Some(Editor::RestoreBackup { backup }) => {
                let backup = *backup.clone();
                self.command(
                    move |store| {
                        let safety = store.restore_backup(&environment, backup)?;
                        Ok((
                            format!(
                                "Backup restored; previous state saved to {}",
                                safety.display()
                            ),
                            None,
                        ))
                    },
                    cx,
                );
            }
            Some(Editor::Idp {
                base_url,
                trust_proxy,
            }) => {
                let base_url = base_url.read(cx).value().to_string();
                let trust_proxy = *trust_proxy;
                self.command(
                    move |store| {
                        store.update_global_config(&GlobalConfigPatch {
                            idp_base_url: Some(base_url),
                            trust_forwarded_headers: Some(trust_proxy),
                            ..Default::default()
                        })?;
                        Ok(("IDP and tunnel settings saved".into(), None))
                    },
                    cx,
                );
            }
            Some(Editor::ConfirmTool { action }) => {
                let action = *action;
                self.command(
                    move |store| {
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
                    },
                    cx,
                );
            }
            Some(Editor::History { .. } | Editor::Tools { .. }) | None => {}
        }
    }
}
