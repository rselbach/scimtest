use super::*;

pub(super) fn resource(value: &Value, kind: &str) -> Result<()> {
    strings(value, &["id", "externalId"])?;
    array_strings(&value["schemas"])?;
    match kind {
        "user" => {
            strings(value, &["userName", "displayName"])?;
            boolean(&value["active"], "active")?;
            strings(&value["name"], &["givenName", "familyName", "formatted"])?;
            for email in array(&value["emails"], "emails")? {
                strings(email, &["value", "type"])?;
                boolean(&email["primary"], "primary")?;
            }
            let enterprise = &value[ENTERPRISE_SCHEMA];
            strings(
                enterprise,
                &[
                    "employeeNumber",
                    "costCenter",
                    "organization",
                    "division",
                    "department",
                ],
            )?;
            strings(&enterprise["manager"], &["value"])?;
        }
        "group" => {
            strings(value, &["displayName"])?;
            for member in array(&value["members"], "members")? {
                strings(member, &["value", "type"])?;
            }
        }
        _ => {}
    }
    Ok(())
}
pub(super) fn list(value: &Value, kind: &str) -> Result<()> {
    strings(value, &[])?;
    for name in ["totalResults", "startIndex", "itemsPerPage"] {
        if !value[name].is_null() && value[name].as_i64().is_none() {
            return Err(Failure::new(format!(
                "decode SCIM response: {name} must be an integer"
            )));
        }
    }
    for item in array(&value["Resources"], "Resources")? {
        resource(item, kind)?;
    }
    Ok(())
}
pub(super) fn capabilities(value: &Value) -> Result<()> {
    strings(value, &[])?;
    for name in ["patch", "filter"] {
        strings(&value[name], &[])?;
        boolean(&value[name]["supported"], "supported")?;
    }
    Ok(())
}
fn strings(value: &Value, names: &[&str]) -> Result<()> {
    if !value.is_object() && !value.is_null() {
        return Err(Failure::new(
            "decode SCIM response: resource must be an object",
        ));
    }
    for name in names {
        if !value[name].is_null() && !value[name].is_string() {
            return Err(Failure::new(format!(
                "decode SCIM response: {name} must be a string"
            )));
        }
    }
    Ok(())
}
fn boolean(value: &Value, name: &str) -> Result<()> {
    if value.is_null() || value.is_boolean() {
        return Ok(());
    }
    Err(Failure::new(format!(
        "decode SCIM response: {name} must be a boolean"
    )))
}
fn array<'a>(value: &'a Value, name: &str) -> Result<&'a [Value]> {
    if value.is_null() {
        return Ok(&[]);
    }
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| Failure::new(format!("decode SCIM response: {name} must be an array")))
}
fn array_strings(value: &Value) -> Result<()> {
    for item in array(value, "schemas")? {
        if !item.is_null() && !item.is_string() {
            return Err(Failure::new(
                "decode SCIM response: schemas must contain strings",
            ));
        }
    }
    Ok(())
}
impl Client {
    pub(super) fn validate(&mut self, result: Result<()>) -> Result<()> {
        if let Err(error) = &result {
            self.trace_error(error);
        }
        result
    }
}
