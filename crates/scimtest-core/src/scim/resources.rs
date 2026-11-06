use super::*;
use crate::model::{Group, User};
use reqwest::Method;
use serde_json::json;

pub fn has_enterprise(user: &User) -> bool {
    let fields = &user.fields;
    [
        &fields.employee_number,
        &fields.cost_center,
        &fields.organization,
        &fields.division,
        &fields.department,
        &fields.manager_id,
    ]
    .iter()
    .any(|value| !value.is_empty())
}
pub fn user_resource(user: &User, users: &[User], enterprise: bool) -> Value {
    let fields = &user.fields;
    let full_name = format!("{} {}", fields.given_name, fields.family_name)
        .trim()
        .to_owned();
    let mut resource = json!({"schemas":[USER_SCHEMA],"externalId":user.id,"userName":fields.username.trim(),
        "displayName":full_name,"active":fields.active,"name":{"givenName":fields.given_name.trim(),"familyName":fields.family_name.trim(),"formatted":full_name},
        "emails":[{"value":fields.email.trim(),"type":"work","primary":true}]});
    if enterprise {
        let manager = users.iter().find(|manager| {
            manager.id == fields.manager_id && !manager.deleted && !manager.remote_id.is_empty()
        });
        resource["schemas"] = json!([USER_SCHEMA, ENTERPRISE_SCHEMA]);
        resource[ENTERPRISE_SCHEMA] = json!({"employeeNumber":fields.employee_number.trim(),"costCenter":fields.cost_center.trim(),
            "organization":fields.organization.trim(),"division":fields.division.trim(),"department":fields.department.trim(),
            "manager":manager.map(|manager| json!({"value":manager.remote_id}))});
    }
    resource
}
pub fn group_resource(group: &Group, users: &[User]) -> Result<Value> {
    let mut members = Vec::new();
    for id in &group.fields.member_ids {
        let user = users.iter().find(|user| user.id == *id).ok_or_else(|| {
            Failure::new(format!(
                "group {:?} references unknown user {id:?}",
                group.fields.display_name
            ))
        })?;
        if user.remote_id.trim().is_empty() {
            return Err(Failure::new(format!(
                "group {:?} member {:?} has not been synced yet",
                group.fields.display_name,
                user_label(user)
            )));
        }
        members.push(json!({"value":user.remote_id,"type":"User"}));
    }
    Ok(
        json!({"schemas":[GROUP_SCHEMA],"externalId":group.id,"displayName":group.fields.display_name.trim(),"members":members}),
    )
}
pub(super) fn user_target(user: &User, operation: &str) -> Target {
    let label = user_label(user);
    let username = user.fields.username.trim();
    Target {
        resource_type: "user".into(),
        resource_id: user.id.clone(),
        label: if username.is_empty() || username == label {
            label
        } else {
            format!("{label} ({username})")
        },
        operation: operation.into(),
    }
}
pub(super) fn group_target(group: &Group, operation: &str) -> Target {
    Target {
        resource_type: "group".into(),
        resource_id: group.id.clone(),
        label: group.fields.display_name.clone(),
        operation: operation.into(),
    }
}
impl Client {
    pub async fn create_user(
        &mut self,
        user: &User,
        users: &[User],
        enterprise: bool,
    ) -> Result<(String, bool)> {
        if let Some(remote) = self
            .find("/Users", &user.id, user_target(user, "adopt"))
            .await?
        {
            let id = string(&remote, "id").to_owned();
            self.write_user(user, users, enterprise, &id, Some(&remote))
                .await?;
            return Ok((id, true));
        }
        let resource = user_resource(user, users, enterprise);
        let response = self
            .request(
                Method::POST,
                "/Users",
                Some(resource),
                true,
                user_target(user, "create"),
            )
            .await?;
        self.validate(validation::resource(&response, "user"))?;
        let id = string(&response, "id");
        if id.is_empty() {
            let error = Failure::new("SCIM create response missing id");
            self.trace_error(&error);
            return Err(error);
        }
        Ok((id.into(), false))
    }
    pub async fn update_user(
        &mut self,
        user: &User,
        users: &[User],
        enterprise: bool,
    ) -> Result<()> {
        let remote = if self.settings.persona == "entra" {
            Some(
                self.find("/Users", &user.id, user_target(user, "adopt"))
                    .await?
                    .ok_or_else(|| missing_match("user", &user.id))?,
            )
        } else {
            None
        };
        let id = remote
            .as_ref()
            .map(|remote| string(remote, "id"))
            .unwrap_or(&user.remote_id);
        self.write_user(user, users, enterprise, id, remote.as_ref())
            .await
    }
    async fn write_user(
        &mut self,
        user: &User,
        users: &[User],
        enterprise: bool,
        id: &str,
        remote: Option<&Value>,
    ) -> Result<()> {
        let mut resource = user_resource(user, users, enterprise);
        let (method, body) = if let Some(remote) =
            remote.filter(|_| self.settings.persona == "entra")
        {
            let operations = entra::user_operations(&resource, remote);
            if operations.is_empty() {
                return Ok(());
            }
            (
                Method::PATCH,
                json!({"schemas":[PATCH_SCHEMA],"Operations":operations}),
            )
        } else if self.settings.scim_patch_supported {
            resource.as_object_mut().unwrap().remove("schemas");
            (
                Method::PATCH,
                json!({"schemas":[PATCH_SCHEMA],"Operations":[{"op":"replace","value":resource}]}),
            )
        } else {
            resource["id"] = json!(id);
            (Method::PUT, resource)
        };
        self.request(
            method,
            &resource_path("/Users", id),
            Some(body),
            false,
            user_target(user, "update"),
        )
        .await?;
        Ok(())
    }
    pub async fn create_group(&mut self, group: &Group, users: &[User]) -> Result<(String, bool)> {
        let resource = group_resource(group, users)?;
        if let Some(remote) = self
            .find("/Groups", &group.id, group_target(group, "adopt"))
            .await?
        {
            let id = string(&remote, "id").to_owned();
            self.write_group(group, resource, &id, Some(&remote))
                .await?;
            return Ok((id, true));
        }
        let response = self
            .request(
                Method::POST,
                "/Groups",
                Some(resource),
                true,
                group_target(group, "create"),
            )
            .await?;
        self.validate(validation::resource(&response, "group"))?;
        let id = string(&response, "id");
        if id.is_empty() {
            let error = Failure::new("SCIM create group response missing id");
            self.trace_error(&error);
            return Err(error);
        }
        Ok((id.into(), false))
    }
    pub async fn update_group(&mut self, group: &Group, users: &[User]) -> Result<()> {
        let remote = if self.settings.persona == "entra" {
            Some(
                self.find("/Groups", &group.id, group_target(group, "adopt"))
                    .await?
                    .ok_or_else(|| missing_match("group", &group.id))?,
            )
        } else {
            None
        };
        let id = remote
            .as_ref()
            .map(|remote| string(remote, "id"))
            .unwrap_or(&group.remote_id);
        self.write_group(group, group_resource(group, users)?, id, remote.as_ref())
            .await
    }
    async fn write_group(
        &mut self,
        group: &Group,
        mut resource: Value,
        id: &str,
        remote: Option<&Value>,
    ) -> Result<()> {
        let (method, body) = if let Some(remote) =
            remote.filter(|_| self.settings.persona == "entra")
        {
            let operations = entra::group_operations(&resource, remote);
            if operations.is_empty() {
                return Ok(());
            }
            (
                Method::PATCH,
                json!({"schemas":[PATCH_SCHEMA],"Operations":operations}),
            )
        } else if self.settings.scim_patch_supported {
            resource.as_object_mut().unwrap().remove("schemas");
            (
                Method::PATCH,
                json!({"schemas":[PATCH_SCHEMA],"Operations":[{"op":"replace","value":resource}]}),
            )
        } else {
            resource["id"] = json!(id);
            (Method::PUT, resource)
        };
        self.request(
            method,
            &resource_path("/Groups", id),
            Some(body),
            false,
            group_target(group, "update"),
        )
        .await?;
        Ok(())
    }
    pub async fn delete_user(&mut self, user: &User) -> Result<()> {
        self.request(
            Method::DELETE,
            &resource_path("/Users", &user.remote_id),
            None,
            false,
            user_target(user, "delete"),
        )
        .await?;
        Ok(())
    }
    pub async fn delete_group(&mut self, group: &Group) -> Result<()> {
        self.request(
            Method::DELETE,
            &resource_path("/Groups", &group.remote_id),
            None,
            false,
            group_target(group, "delete"),
        )
        .await?;
        Ok(())
    }
    pub async fn get_user(&mut self, user: &User) -> Result<Value> {
        let value = self
            .request(
                Method::GET,
                &resource_path("/Users", &user.remote_id),
                None,
                true,
                user_target(user, "check"),
            )
            .await?;
        self.validate(validation::resource(&value, "user"))?;
        Ok(value)
    }
    pub async fn get_group(&mut self, group: &Group) -> Result<Value> {
        let value = self
            .request(
                Method::GET,
                &resource_path("/Groups", &group.remote_id),
                None,
                true,
                group_target(group, "check"),
            )
            .await?;
        self.validate(validation::resource(&value, "group"))?;
        Ok(value)
    }
}

fn missing_match(kind: &str, id: &str) -> Failure {
    Failure {
        status: 404,
        ..Failure::new(format!(
            "SCIM {kind} with externalId {id:?}: resource not found"
        ))
    }
}
