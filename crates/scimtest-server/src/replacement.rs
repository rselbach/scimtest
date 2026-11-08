use crate::{
    auth::{self, GitHubUser, field},
    enrollment::{Hash, hash, unique_hex},
    lock,
    server::{State, error},
};
use anyhow::{Result, bail};
use axum::{extract::Request, http::StatusCode, response::Response};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use serde_json::json;

const COOKIE: &str = "scimtest_enrollment_replacement";
const EXPIRED: &str = "installation replacement is invalid or expired";
const FORBIDDEN: &str = "the selected installation cannot be replaced";

#[derive(Clone)]
pub(crate) struct ReplacementIntent {
    pub enrollment: Hash,
    user: GitHubUser,
    csrf: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct OptionView {
    #[serde(rename = "InstanceID")]
    instance_id: String,
    display_name: String,
    activity: String,
    created: String,
    connected: bool,
    pending: bool,
    recommended: bool,
    #[serde(skip)]
    last_used: Option<DateTime<Utc>>,
}

impl State {
    pub fn replacement_page(
        &self,
        device: Hash,
        user: GitHubUser,
        notice: &str,
    ) -> Result<Response> {
        let now = Utc::now();
        let mut state = lock(&self.enrollment);
        state.prune(now);
        let pending = state
            .pending
            .get(&device)
            .filter(|pending| pending.approved_at.is_none())
            .cloned()
            .ok_or_else(|| anyhow::anyhow!(EXPIRED))?;
        let profile = self
            .store
            .profile(&pending.binding.profile)?
            .ok_or_else(|| anyhow::anyhow!("application profile not found"))?;
        let active = lock(&self.tunnels)
            .values()
            .filter(|tunnel| tunnel.profile_id == profile.id)
            .map(|tunnel| tunnel.instance_id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let mut options = Vec::new();
        for (id, instance) in &profile.instances {
            if !instance.is_enrolled() || instance.revoked || instance.github_user_id != user.id {
                continue;
            }
            options.push(OptionView {
                instance_id: id.clone(),
                display_name: if instance.tunnel_id.is_empty() {
                    id.clone()
                } else {
                    instance.tunnel_id.clone()
                },
                activity: format!("Last used {}", format_time(instance.last_used_at)),
                created: format_time(instance.created_at),
                connected: active.contains(id),
                pending: false,
                recommended: false,
                last_used: Some(instance.last_used_at),
            });
        }
        for (other, approval) in &state.pending {
            if *other == device
                || approval.binding.profile != profile.id
                || approval.approved_at.is_none()
                || approval
                    .actor
                    .as_ref()
                    .is_none_or(|actor| actor.id != user.id)
            {
                continue;
            }
            options.push(OptionView {
                instance_id: approval.binding.instance.clone(),
                display_name: approval.binding.instance.clone(),
                activity: "Authorization approved; never connected".into(),
                created: format_time(approval.created_at),
                connected: false,
                pending: true,
                recommended: false,
                last_used: None,
            });
        }
        if options.is_empty() {
            bail!("no existing installation is available to replace");
        }
        options.sort_by(|left, right| {
            left.connected
                .cmp(&right.connected)
                .then_with(|| left.last_used.cmp(&right.last_used))
                .then_with(|| left.instance_id.cmp(&right.instance_id))
        });
        if let Some(option) = options.iter_mut().find(|option| !option.connected) {
            option.recommended = true;
        }
        let token = unique_hex(32, |value| state.replacements.contains_key(&hash(value)))?;
        let csrf = auth::random_hex(24)?;
        let expiry = pending.expires_at.min(now + Duration::minutes(10));
        let max_age = (expiry - now).num_seconds();
        if max_age < 1 {
            bail!(EXPIRED);
        }
        state
            .replacements
            .retain(|_, intent| intent.enrollment != device);
        state.replacements.insert(
            hash(&token),
            ReplacementIntent {
                enrollment: device,
                user: user.clone(),
                csrf: csrf.clone(),
                expires_at: expiry,
            },
        );
        drop(state);
        let mut response = self.page("replacement.html", json!({"ApplicationName":profile.settings.name,"GitHubLogin":user.login.trim(),"InstanceFingerprint":pending.binding.instance,"Limit":self.config.max_installations_per_user,"CSRFToken":csrf,"Notice":notice,"Options":options}));
        self.set_cookie(
            &mut response,
            COOKIE,
            &token,
            &format!("Strict; Max-Age={max_age}"),
        );
        response.headers_mut().insert(
            "referrer-policy",
            axum::http::HeaderValue::from_static("strict-origin"),
        );
        Ok(response)
    }

    pub async fn replace_enrollment(&self, request: Request) -> Response {
        if request.method() != "POST" {
            return auth::method_not_allowed("POST");
        }
        if !self.allowed_mutation(&request) {
            return error(StatusCode::FORBIDDEN, "invalid replacement origin");
        }
        let token = auth::cookie(request.headers(), &self.cookie_name(COOKIE))
            .unwrap_or("")
            .to_owned();
        let values = match auth::form(request, 4 << 10).await {
            Ok(values) => values,
            Err(_) => return error(StatusCode::BAD_REQUEST, "invalid installation replacement"),
        };
        let instance = field(&values, "instance_id");
        if !crate::application::valid_instance_id(instance) {
            return error(StatusCode::BAD_REQUEST, "invalid installation replacement");
        }
        if !auth::valid_hex(&token, 64) {
            return error(StatusCode::GONE, EXPIRED);
        }
        let intent = {
            let mut state = lock(&self.enrollment);
            state.prune(Utc::now());
            let Some(intent) = state.replacements.get(&hash(&token)) else {
                return error(StatusCode::GONE, EXPIRED);
            };
            if !auth::equal_secret(&intent.csrf, field(&values, "csrf_token")) {
                return error(StatusCode::BAD_REQUEST, "invalid installation replacement");
            }
            state
                .replacements
                .remove(&hash(&token))
                .expect("intent exists under lock")
        };
        let result = self.replace(&intent, instance);
        let mut response = match result {
            Ok(()) => self.page("complete.html", json!({})),
            Err(error) if error.to_string() == FORBIDDEN => self
                .replacement_page(
                    intent.enrollment,
                    intent.user,
                    "That installation is no longer available. Choose another.",
                )
                .unwrap_or_else(|_| {
                    crate::server::error(StatusCode::INTERNAL_SERVER_ERROR, FORBIDDEN)
                }),
            Err(error) => crate::server::error(
                if error.to_string() == EXPIRED {
                    StatusCode::GONE
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                },
                &error.to_string(),
            ),
        };
        // A refreshed chooser must keep its new replacement cookie.
        let has_replacement = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .any(|value| {
                value
                    .to_str()
                    .is_ok_and(|value| value.starts_with(&format!("{}=", self.cookie_name(COOKIE))))
            });
        if !has_replacement {
            self.clear_cookie(&mut response, COOKIE);
        }
        response
    }

    fn replace(&self, intent: &ReplacementIntent, instance: &str) -> Result<()> {
        let mut state = lock(&self.enrollment);
        state.prune(Utc::now());
        let pending = state
            .pending
            .get(&intent.enrollment)
            .filter(|pending| pending.approved_at.is_none())
            .cloned()
            .ok_or_else(|| anyhow::anyhow!(EXPIRED))?;
        self.prune_idle(&pending.binding.profile)?;
        let count = self
            .store
            .count_instances_for_user(&pending.binding.profile, intent.user.id)?
            + state.approved_count(intent.enrollment, &pending.binding.profile, intent.user.id);
        let mut disconnect = false;
        if count >= self.config.max_installations_per_user {
            disconnect = self.store.revoke_instance_for_user(
                &pending.binding.profile,
                instance,
                intent.user.id,
            )?;
            if !disconnect {
                let other = state
                    .pending
                    .iter()
                    .find(|(hash, other)| {
                        **hash != intent.enrollment
                            && other.binding.profile == pending.binding.profile
                            && other.binding.instance == instance
                            && other.approved_at.is_some()
                            && other
                                .actor
                                .as_ref()
                                .is_some_and(|user| user.id == intent.user.id)
                    })
                    .map(|(hash, _)| *hash);
                let Some(other) = other else {
                    bail!(FORBIDDEN);
                };
                state.remove(other);
            }
        }
        state.approve(intent.enrollment, intent.user.clone(), Utc::now());
        drop(state);
        if disconnect {
            self.disconnect_instance(&pending.binding.profile, instance);
        }
        Ok(())
    }
}

fn format_time(value: DateTime<Utc>) -> String {
    if value.year() == 1 {
        return "never".into();
    }
    value.format("%b %-d, %Y at %H:%M UTC").to_string()
}

use chrono::Datelike;
