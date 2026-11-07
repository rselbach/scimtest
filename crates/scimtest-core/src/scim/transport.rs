use super::*;
use chrono::{DateTime, Utc};
use reqwest::Method;
use std::time::Duration;

impl Client {
    pub async fn request(
        &mut self,
        method: Method,
        path: &str,
        body: Option<Value>,
        decode: bool,
        target: Target,
    ) -> Result<Value> {
        let payload = body
            .map(|value| serde_json::to_string(&value))
            .transpose()
            .map_err(|error| Failure::new(error.to_string()))?;
        for attempt in 0..=3 {
            let result = self
                .request_once(method.clone(), path, payload.as_deref(), decode, &target)
                .await;
            let error = match result {
                Ok(value) => return Ok(value),
                Err(error) => error,
            };
            if error.status != 429 || attempt == 3 {
                return Err(error);
            }
            let delay = retry_delay(&error.retry_after, Utc::now())
                .unwrap_or(Duration::from_secs(1 << attempt));
            if delay > Duration::from_secs(30) {
                return Err(error);
            }
            if let Some(callback) = &self.on_rate_limit {
                callback(&target, delay, &error.retry_after, attempt + 1);
            }
            tokio::select! {
                _ = self.cancellation.wait() => return Err(cancelled()),
                _ = tokio::time::sleep(delay) => {}
            }
        }
        unreachable!()
    }
    async fn request_once(
        &mut self,
        method: Method,
        path: &str,
        payload: Option<&str>,
        decode: bool,
        target: &Target,
    ) -> Result<Value> {
        let mut trace = Trace {
            resource_type: target.resource_type.clone(),
            resource_id: target.resource_id.clone(),
            label: target.label.clone(),
            operation: target.operation.clone(),
            method: method.to_string(),
            path: path.into(),
            request_body: payload.unwrap_or_default().into(),
            created_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            ..Default::default()
        };
        let result = tokio::select! {
            biased;
            _ = self.cancellation.wait() => Err(cancelled()),
            result = self.perform(method,path,payload,decode,&mut trace) => result,
        };
        if let Err(error) = &result {
            trace.err = error.to_string();
        }
        self.traces.push(trace);
        result
    }
    async fn perform(
        &self,
        method: Method,
        path: &str,
        payload: Option<&str>,
        decode: bool,
        trace: &mut Trace,
    ) -> Result<Value> {
        let mut request = self
            .http
            .request(
                method.clone(),
                format!(
                    "{}{path}",
                    self.settings.scim_base_url.trim_end_matches('/')
                ),
            )
            .bearer_auth(&self.settings.scim_bearer_token)
            .header("Accept", "application/scim+json");
        if let Some(payload) = payload {
            request = request
                .header("Content-Type", "application/scim+json")
                .body(payload.to_owned());
        }
        let mut response = request.send().await?;
        let status = response.status();
        trace.status = format!(
            "{} {}",
            status.as_u16(),
            status.canonical_reason().unwrap_or_default()
        );
        trace.response_retry_after = response
            .headers()
            .get("Retry-After")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .trim()
            .into();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len() + chunk.len() > 10 << 20 {
                return Err(Failure::new("SCIM response body exceeds 10 MiB"));
            }
            bytes.extend_from_slice(&chunk);
        }
        trace.response_body = String::from_utf8_lossy(&bytes).trim().into();
        if !status.is_success() {
            if method == Method::DELETE && [404, 410].contains(&status.as_u16()) {
                return Ok(Value::Null);
            }
            let message = if status.as_u16() == 429 {
                format!(
                    "SCIM server rate limit hit ({}). Try again {}.",
                    trace.status,
                    if trace.response_retry_after.is_empty() {
                        "later".into()
                    } else {
                        human_retry_after(&trace.response_retry_after, Utc::now())
                    }
                )
            } else {
                format!(
                    "SCIM {method} {path} returned {}: {}{}",
                    trace.status,
                    if [404, 410].contains(&status.as_u16()) {
                        "resource not found"
                    } else {
                        &trace.response_body
                    },
                    if payload.is_some() && ![404, 410].contains(&status.as_u16()) {
                        format!(" | request body: {}", payload.unwrap_or_default())
                    } else {
                        String::new()
                    }
                )
            };
            return Err(Failure {
                message,
                status: status.as_u16(),
                retry_after: trace.response_retry_after.clone(),
                cancelled: false,
            });
        }
        if !decode || bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&bytes)
            .map_err(|error| Failure::new(format!("decode SCIM {method} {path} response: {error}")))
    }
    pub(super) fn trace_error(&mut self, error: &Failure) {
        if let Some(trace) = self.traces.last_mut() {
            trace.err = error.to_string();
        }
    }
    pub async fn list(
        &mut self,
        collection: &str,
        resource_type: &str,
        operation: &str,
    ) -> Result<Vec<Value>> {
        let mut resources = Vec::new();
        let mut start = 1u64;
        loop {
            let path = format!("{collection}?startIndex={start}&count=100");
            let page = self
                .request(
                    Method::GET,
                    &path,
                    None,
                    true,
                    Target {
                        resource_type: resource_type.into(),
                        label: format!("SCIM {collection}"),
                        operation: operation.into(),
                        ..Default::default()
                    },
                )
                .await?;
            self.validate(validation::list(&page, resource_type))?;
            let items = page["Resources"].as_array().cloned().unwrap_or_default();
            let length = items.len() as u64;
            resources.extend(items);
            if length == 0 {
                return Ok(resources);
            }
            let current = page["startIndex"]
                .as_u64()
                .filter(|value| *value > 0)
                .unwrap_or(start);
            let next = current
                .checked_add(length)
                .ok_or_else(|| Failure::new("SCIM pagination index overflow"))?;
            let total = page["totalResults"].as_u64().unwrap_or_default();
            let per_page = page["itemsPerPage"].as_u64().unwrap_or_default();
            if total > 0 && next > total
                || per_page > 0 && length < per_page
                || total == 0 && per_page == 0 && length < 100
            {
                return Ok(resources);
            }
            if next <= start {
                return Err(Failure::new(format!(
                    "SCIM {collection} pagination did not advance from startIndex {start}"
                )));
            }
            start = next;
        }
    }
    pub async fn find(
        &mut self,
        collection: &str,
        id: &str,
        target: Target,
    ) -> Result<Option<Value>> {
        let filter = format!(
            "externalId eq {}",
            serde_json::to_string(id).map_err(|error| Failure::new(error.to_string()))?
        );
        let mut parameters = vec![("filter", filter)];
        if self.settings.persona != "entra" {
            parameters.push(("count", "2".into()));
        }
        let query = serde_urlencoded::to_string(parameters)
            .map_err(|error| Failure::new(error.to_string()))?;
        let path = format!("{collection}?{query}");
        let lookup = self
            .request(Method::GET, &path, None, true, target.clone())
            .await
            .and_then(|value| {
                self.validate(validation::list(&value, &target.resource_type))?;
                Ok(value)
            });
        let page = match lookup {
            Ok(value) => value,
            Err(error)
                if !self.settings.scim_filter_supported
                    && self.settings.persona != "entra"
                    && !error.stops_sync() =>
            {
                let resources = self
                    .list(collection, &target.resource_type, "adopt")
                    .await?;
                serde_json::json!({"Resources":resources.into_iter().filter(|value| string(value,"externalId") == id).collect::<Vec<_>>()})
            }
            Err(error) => return Err(error),
        };
        let items = page["Resources"].as_array().cloned().unwrap_or_default();
        let error = if page["totalResults"].as_u64().unwrap_or_default() > 1 || items.len() > 1 {
            Some(Failure::new(format!(
                "SCIM filter for externalId {id:?} returned multiple resources"
            )))
        } else if page["totalResults"].as_u64().unwrap_or_default() > 0 && items.is_empty() {
            Some(Failure::new(format!(
                "SCIM filter for externalId {id:?} reported a match without returning it"
            )))
        } else if let Some(resource) = items.first() {
            if resource["externalId"].as_str().unwrap_or_default() != id {
                Some(Failure::new(format!(
                    "SCIM filter for externalId {id:?} returned another externalId"
                )))
            } else if string(resource, "id").is_empty() {
                Some(Failure::new(format!(
                    "SCIM resource matched by externalId {id:?} is missing id"
                )))
            } else {
                None
            }
        } else {
            None
        };
        if let Some(error) = error {
            self.trace_error(&error);
            return Err(error);
        }
        Ok(items.into_iter().next())
    }
}
fn cancelled() -> Failure {
    Failure {
        cancelled: true,
        ..Failure::new("SCIM operation cancelled")
    }
}
fn retry_delay(value: &str, now: DateTime<Utc>) -> Option<Duration> {
    if let Ok(seconds) = value.parse::<i64>() {
        return Some(Duration::from_secs(seconds.max(0) as u64));
    }
    let time = httpdate::parse_http_date(value).ok()?;
    Some(time.duration_since(now.into()).unwrap_or_default())
}
pub fn human_retry_after(value: &str, now: DateTime<Utc>) -> String {
    if value == "now" || value.starts_with("in ") || value.starts_with("after ") {
        return value.into();
    }
    let delay = retry_delay(value, now).or_else(|| {
        crate::duration::parse(value).map(|duration| Duration::from_nanos(duration.max(0) as u64))
    });
    let Some(delay) = delay else {
        return format!("after {value}");
    };
    let seconds = delay.as_secs_f64().ceil() as u64;
    if seconds == 0 {
        return "now".into();
    }
    let (amount, unit) = if seconds < 60 {
        (seconds, "second")
    } else if seconds < 3600 {
        (seconds.div_ceil(60), "minute")
    } else if seconds < 86400 {
        (seconds.div_ceil(3600), "hour")
    } else {
        (seconds.div_ceil(86400), "day")
    };
    format!("in {amount} {unit}{}", if amount == 1 { "" } else { "s" })
}
