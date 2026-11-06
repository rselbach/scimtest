use super::*;
use crate::{
    Store,
    model::{Directory, OperationLog, ResourceSyncState},
};

impl Store {
    pub(super) fn save_sync_result(
        &self,
        id: &str,
        result: &SyncResult,
        mode: &Mode,
    ) -> std::result::Result<(), Error> {
        self.edit_internal(id, |directory| {
            if result.enterprise {
                directory
                    .config
                    .insert("scim_enterprise_used".into(), "1".into());
            }
            let selected = |kind: &str, id: &str| match mode {
                Mode::Push {
                    resource_type,
                    resource_id,
                } => resource_type == kind && resource_id == id,
                _ => true,
            };
            for user in &directory.users {
                if !selected("user", &user.id) {
                    continue;
                }
                let state = result
                    .users
                    .iter()
                    .find(|synced| synced.id == user.id)
                    .map(|synced| ResourceSyncState {
                        remote_id: synced.remote_id.clone(),
                        dirty: synced.dirty,
                        deleted: synced.deleted,
                        last_error: synced.last_error.clone(),
                    })
                    .unwrap_or(ResourceSyncState {
                        deleted: true,
                        ..Default::default()
                    });
                directory.user_sync.insert(user.id.clone(), state);
            }
            for group in &directory.groups {
                if !selected("group", &group.id) {
                    continue;
                }
                let state = result
                    .groups
                    .iter()
                    .find(|synced| synced.id == group.id)
                    .map(|synced| ResourceSyncState {
                        remote_id: synced.remote_id.clone(),
                        dirty: synced.dirty,
                        deleted: synced.deleted,
                        last_error: synced.last_error.clone(),
                    })
                    .unwrap_or(ResourceSyncState {
                        deleted: true,
                        ..Default::default()
                    });
                directory.group_sync.insert(group.id.clone(), state);
            }
            append_traces(directory, &result.traces);
            purge(directory);
            Ok(())
        })
    }
    pub fn reset_scim(&self, id: &str) -> std::result::Result<(usize, usize), Error> {
        self.edit(id, |directory| {
            if !directory.environment.settings.scim_enabled {
                return Err(Error::Validation(
                    "SCIM is not enabled for the environment".into(),
                ));
            }
            directory.user_sync = directory
                .users
                .iter()
                .map(|user| {
                    (
                        user.id.clone(),
                        ResourceSyncState {
                            dirty: true,
                            deleted: user.deleted,
                            ..Default::default()
                        },
                    )
                })
                .collect();
            directory.group_sync = directory
                .groups
                .iter()
                .map(|group| {
                    (
                        group.id.clone(),
                        ResourceSyncState {
                            dirty: true,
                            deleted: group.deleted,
                            ..Default::default()
                        },
                    )
                })
                .collect();
            Ok((directory.users.len(), directory.groups.len()))
        })
    }
    pub(super) fn set_scim_capabilities(
        &self,
        id: &str,
        patch: bool,
        filter: bool,
        traces: &[Trace],
    ) -> std::result::Result<(), Error> {
        self.edit(id, |directory| {
            let settings = &mut directory.environment.settings;
            settings.scim_capabilities_known = true;
            settings.scim_patch_supported = patch;
            settings.scim_filter_supported = filter;
            append_traces(directory, traces);
            Ok(())
        })
    }
}
pub(super) fn append_traces(directory: &mut Directory, traces: &[Trace]) {
    for trace in traces {
        let operations = match trace.resource_type.as_str() {
            "user" => &mut directory.user_operations,
            "group" => &mut directory.group_operations,
            _ => continue,
        };
        let summary = if !trace.err.is_empty() {
            if trace.operation.trim().is_empty() {
                "Failed".into()
            } else {
                format!("Failed to {}", trace.operation.trim())
            }
        } else {
            match trace.operation.as_str() {
                "create" => "Created".into(),
                "delete" => "Deleted".into(),
                _ => "Synced".into(),
            }
        };
        let entry = OperationLog {
            app_id: directory.environment.id.clone(),
            kind: "sync".into(),
            summary,
            operation: trace.operation.clone(),
            method: trace.method.clone(),
            path: trace.path.clone(),
            request_body: trace.request_body.clone(),
            status: trace.status.clone(),
            response_retry_after: trace.response_retry_after.clone(),
            response_body: trace.response_body.clone(),
            err: trace.err.clone(),
            created_at: trace.created_at.clone(),
            ..Default::default()
        };
        let entries = operations.entry(trace.resource_id.clone()).or_default();
        entries.insert(0, entry);
        entries.truncate(100);
    }
}
pub(super) fn purge(directory: &mut Directory) {
    let settled = |state: Option<&ResourceSyncState>| {
        state.is_some_and(|state| state.deleted && !state.dirty && state.remote_id.is_empty())
    };
    let users = directory
        .users
        .iter()
        .filter(|user| user.deleted && settled(directory.user_sync.get(&user.id)))
        .map(|user| user.id.clone())
        .collect::<std::collections::HashSet<_>>();
    directory.users.retain(|user| !users.contains(&user.id));
    directory.user_sync.retain(|id, _| !users.contains(id));
    directory
        .user_operations
        .retain(|id, _| !users.contains(id));
    for group in &mut directory.groups {
        group.fields.member_ids.retain(|id| !users.contains(id));
    }
    let groups = directory
        .groups
        .iter()
        .filter(|group| group.deleted && settled(directory.group_sync.get(&group.id)))
        .map(|group| group.id.clone())
        .collect::<std::collections::HashSet<_>>();
    directory.groups.retain(|group| !groups.contains(&group.id));
    directory.group_sync.retain(|id, _| !groups.contains(id));
    directory
        .group_operations
        .retain(|id, _| !groups.contains(id));
}
