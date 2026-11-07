use super::*;
use serde_json::json;

pub(super) fn user_operations(desired: &Value, remote: &Value) -> Vec<Value> {
    let mut operations = Vec::new();
    for (path, want, have) in [
        (
            "userName",
            string(desired, "userName"),
            string(remote, "userName"),
        ),
        (
            "displayName",
            string(desired, "displayName"),
            string(remote, "displayName"),
        ),
        (
            "name.givenName",
            string(&desired["name"], "givenName"),
            string(&remote["name"], "givenName"),
        ),
        (
            "name.familyName",
            string(&desired["name"], "familyName"),
            string(&remote["name"], "familyName"),
        ),
        (
            "emails[type eq \"work\"].value",
            email(desired),
            email(remote),
        ),
        (
            "externalId",
            string(desired, "externalId"),
            string(remote, "externalId"),
        ),
    ] {
        set(&mut operations, path, want, have);
    }
    if desired["active"].as_bool().unwrap_or(true) != remote["active"].as_bool().unwrap_or(true) {
        operations.push(json!({"op":"Replace","path":"active","value":if desired["active"] == true { "True" } else { "False" }}));
    }
    if desired.get(ENTERPRISE_SCHEMA).is_some() {
        for name in [
            "employeeNumber",
            "costCenter",
            "organization",
            "division",
            "department",
            "manager",
        ] {
            let path = format!("{ENTERPRISE_SCHEMA}:{name}");
            let field = |value: &Value| {
                if name == "manager" {
                    string(&value[ENTERPRISE_SCHEMA]["manager"], "value").to_owned()
                } else {
                    string(&value[ENTERPRISE_SCHEMA], name).to_owned()
                }
            };
            set(&mut operations, &path, &field(desired), &field(remote));
        }
    }
    operations
}
pub(super) fn group_operations(desired: &Value, remote: &Value) -> Vec<Value> {
    let mut operations = Vec::new();
    if string(desired, "displayName") != string(remote, "displayName") {
        operations
            .push(json!({"op":"Replace","path":"displayName","value":desired["displayName"]}));
    }
    let members = |value: &Value| {
        value["members"]
            .as_array()
            .map(|members| {
                members
                    .iter()
                    .map(|member| string(member, "value").to_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    let want = members(desired);
    let have = members(remote);
    let added = want
        .iter()
        .filter(|member| !have.contains(member))
        .map(|value| json!({"value":value}))
        .collect::<Vec<_>>();
    let removed = have
        .iter()
        .filter(|member| !want.contains(member))
        .map(|value| json!({"value":value}))
        .collect::<Vec<_>>();
    if !added.is_empty() {
        operations.push(json!({"op":"Add","path":"members","value":added}));
    }
    if !removed.is_empty() {
        operations.push(json!({"op":"Remove","path":"members","value":removed}));
    }
    operations
}
fn set(operations: &mut Vec<Value>, path: &str, want: &str, have: &str) {
    if want == have {
        return;
    }
    let operation = if want.is_empty() {
        json!({"op":"Remove","path":path})
    } else {
        json!({"op":"Replace","path":path,"value":want})
    };
    operations.push(operation);
}
pub(super) fn email(resource: &Value) -> &str {
    let Some(emails) = resource["emails"].as_array() else {
        return "";
    };
    emails
        .iter()
        .map(|email| string(email, "value"))
        .find(|value| !value.is_empty())
        .unwrap_or_default()
}
