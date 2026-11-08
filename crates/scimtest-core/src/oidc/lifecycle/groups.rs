use super::*;
use std::collections::HashSet;

pub(super) struct GroupChange {
    pub environment: Environment,
    pub user: User,
    pub added: Vec<Group>,
    pub removed: Vec<Group>,
    pub groups: Vec<String>,
}
impl GroupChange {
    pub fn describe(&self) -> String {
        let names = |groups: &[Group]| {
            groups
                .iter()
                .map(|group| group.fields.display_name.clone())
                .collect::<Vec<_>>()
                .join(", ")
        };
        match (self.added.is_empty(), self.removed.is_empty()) {
            (false, false) => format!(
                "Added to {}; removed from {}",
                names(&self.added),
                names(&self.removed)
            ),
            (false, true) => format!("Added to {}", names(&self.added)),
            _ => format!("Removed from {}", names(&self.removed)),
        }
    }
}
pub(super) fn change_groups(
    store: &Store,
    id: &str,
    user_id: &str,
    added: &[String],
    removed: &[String],
    require_active: bool,
) -> std::result::Result<GroupChange, Error> {
    if added.is_empty() && removed.is_empty() {
        return Err(Error::Validation(
            "choose at least one group to add or remove".into(),
        ));
    }
    store.edit(id, |directory| {
        let user = directory
            .users
            .iter()
            .find(|user| user.id == user_id && !user.deleted)
            .cloned()
            .ok_or_else(|| Error::Validation(format!("user {user_id:?} not found")))?;
        let name = label(&user);
        if require_active && !user.fields.active {
            return Err(Error::Validation(format!(
                "{name} is inactive; activate the user before moving them"
            )));
        }
        let mut change = GroupChange {
            environment: directory.environment.clone(),
            user,
            added: Vec::new(),
            removed: Vec::new(),
            groups: Vec::new(),
        };
        let mut seen = HashSet::new();
        for (ids, adding) in [(added, true), (removed, false)] {
            for group_id in ids {
                let group = directory
                    .groups
                    .iter_mut()
                    .find(|group| group.id == *group_id && !group.deleted)
                    .ok_or_else(|| Error::Validation(format!("group {group_id:?} not found")))?;
                let group_name = &group.fields.display_name;
                if !seen.insert(group_id.clone()) {
                    return Err(Error::Validation(format!(
                        "group {group_name} is listed more than once"
                    )));
                }
                let member = group
                    .fields
                    .member_ids
                    .iter()
                    .any(|member| member == user_id);
                if adding && member {
                    return Err(Error::Validation(format!(
                        "{name} is already in {group_name}"
                    )));
                }
                if !adding && !member {
                    return Err(Error::Validation(format!("{name} is not in {group_name}")));
                }
                group.fields.member_ids.retain(|member| member != user_id);
                if adding {
                    group.fields.member_ids.push(user_id.into());
                }
                group.dirty = true;
                group.last_error.clear();
                if adding {
                    change.added.push(group.clone());
                } else {
                    change.removed.push(group.clone());
                }
                directory.mark_group_dirty(group_id, false);
                directory.local_operation("group", group_id, "Updated members");
            }
        }
        change.groups = directory
            .groups
            .iter()
            .filter(|group| {
                !group.deleted
                    && group
                        .fields
                        .member_ids
                        .iter()
                        .any(|member| member == user_id)
            })
            .map(|group| group.fields.display_name.clone())
            .collect();
        Ok(change)
    })
}

pub(super) fn issued_step(
    environment: &Environment,
    protocol: &str,
    user: &str,
    groups: &[String],
) -> LifecycleStep {
    let settings = &environment.settings;
    let (enabled, name, title, waiting) = if protocol == "oidc" {
        (
            settings.supports_oidc(),
            "OIDC",
            "Next ID token or userinfo response carries the new groups",
            format!(
                "the next ID token or userinfo response for {user}. The app must request the groups scope"
            ),
        )
    } else {
        (
            settings.supports_saml(),
            "SAML",
            "Next SAML assertion carries the new groups",
            format!("the next SAML assertion for {user}"),
        )
    };
    let (status, detail) = if !enabled {
        (
            "skipped",
            format!("{name} is not enabled for this environment"),
        )
    } else if !settings.include_groups_claim {
        (
            "skipped",
            "The environment does not send groups; turn on the groups claim to check them".into(),
        )
    } else {
        (
            "waiting",
            format!(
                "Waiting for {waiting}. Expected groups: {}",
                describe(groups)
            ),
        )
    };
    LifecycleStep::new(
        &format!("{protocol}-groups"),
        protocol,
        title,
        status,
        detail,
    )
}
fn describe(groups: &[String]) -> String {
    if groups.is_empty() {
        return "none".into();
    }
    groups.join(", ")
}
pub(in crate::oidc) struct IssuedGroups {
    pub groups: Vec<String>,
    pub carried: bool,
    pub overage: bool,
}
impl IssuedGroups {
    pub fn claims(claims: &Value, name: &str) -> Self {
        let value = claims.get(name).filter(|_| !name.is_empty());
        let source = claims["_claim_names"][name].as_str().unwrap_or_default();
        let overage = !name.is_empty()
            && claims["_claim_sources"][source]["endpoint"]
                .as_str()
                .is_some_and(|value| !value.is_empty());
        let groups = match value {
            Some(Value::Array(values)) => values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| value.to_string())
                })
                .collect(),
            None | Some(Value::Null) => Vec::new(),
            Some(value) => vec![
                value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string()),
            ],
        };
        Self {
            groups,
            carried: value.is_some(),
            overage: value.is_none() && overage,
        }
    }
}
impl Memory {
    pub(in crate::oidc) fn note_groups(
        &mut self,
        directory: &Directory,
        user_id: &str,
        protocol: &str,
        issued: &str,
        to: &str,
        claims: IssuedGroups,
    ) {
        let environment = &directory.environment;
        for run in self
            .lifecycle
            .get_mut(&environment.id)
            .into_iter()
            .flatten()
        {
            if run.kind != "mover" || run.user_id != user_id {
                continue;
            }
            let Some(step) = run
                .steps
                .iter_mut()
                .find(|step| step.id == format!("{protocol}-groups") && step.status == "waiting")
            else {
                continue;
            };
            let mut want = run.expected_groups.clone();
            if protocol == "oidc"
                && environment.settings.persona == "okta"
                && !want.iter().any(|group| group == "Everyone")
            {
                want.push("Everyone".into());
            }
            let mut got = claims.groups.clone();
            want.sort();
            got.sort();
            let body = if claims.overage
                && protocol == "oidc"
                && environment.settings.persona == "entra"
            {
                step.detail = format!(
                    "The {issued} carried groups overage; waiting for the group source response"
                );
                "groups overage".into()
            } else if !claims.carried {
                step.status = "failed".into();
                step.detail = format!("The {issued} carried no groups");
                "no groups".into()
            } else {
                if got == want {
                    step.status = "ok".into();
                    step.detail = format!(
                        "The {issued} carried the new groups: {}",
                        describe(&claims.groups)
                    );
                } else {
                    step.status = "failed".into();
                    step.detail = format!(
                        "The {issued} carried {}; expected {}",
                        describe(&claims.groups),
                        describe(&run.expected_groups)
                    );
                }
                format!("groups: {}", describe(&claims.groups))
            };
            step.messages.push(LifecycleMessage {
                at: timestamp(),
                sent: issued.into(),
                to: to.into(),
                body,
                response: String::new(),
                outcome: step.status.clone(),
            });
            run.settle_status();
        }
    }
}
